//! Bounded blocking upstream workers; they never hold up the packet loop.
use super::resolver::MAX_MESSAGE;
use hickory_proto::op::{Message, MessageType};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    thread,
    time::{Duration, Instant},
};

pub(super) struct Job {
    pub id: u64,
    pub query: Message,
    pub servers: Vec<SocketAddr>,
    pub deadline: Instant,
}
pub(super) struct Completed {
    pub id: u64,
    pub response: Option<Message>,
}
pub(super) struct Pool {
    pub jobs: SyncSender<Job>,
    pub results: Receiver<Completed>,
}
impl Pool {
    pub fn new() -> io::Result<Self> {
        let (jobs, rx) = sync_channel::<Job>(32);
        let (tx, results) = sync_channel(64);
        let rx = Arc::new(Mutex::new(rx));
        for index in 0..4 {
            let (rx, tx) = (rx.clone(), tx.clone());
            thread::Builder::new()
                .name(format!("dns-upstream-{index}"))
                .spawn(move || {
                    loop {
                        let job = {
                            let Ok(rx) = rx.lock() else {
                                return;
                            };
                            rx.recv()
                        };
                        let Ok(job) = job else {
                            return;
                        };
                        let response = job.servers.iter().find_map(|server| {
                            if Instant::now() >= job.deadline {
                                return None;
                            }
                            exchange(*server, &job.query, job.deadline).ok()
                        });
                        let _ = tx.try_send(Completed {
                            id: job.id,
                            response,
                        });
                    }
                })?;
        }
        Ok(Self { jobs, results })
    }
}
fn timeout(deadline: Instant) -> io::Result<Duration> {
    let left = deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(1));
    if left.is_zero() {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(left)
}
fn exchange(server: SocketAddr, query: &Message, deadline: Instant) -> io::Result<Message> {
    // TCP protects transaction matching and avoids fragmented upstream UDP.
    let mut stream = TcpStream::connect_timeout(&server, timeout(deadline)?)?;
    stream.set_read_timeout(Some(timeout(deadline)?))?;
    stream.set_write_timeout(Some(timeout(deadline)?))?;
    let mut wire = query.clone();
    wire.metadata.id = wgfeel_host::random_seed().map_err(io::Error::other)? as u16;
    let bytes = wire.to_vec().map_err(io::Error::other)?;
    stream.write_all(&(bytes.len() as u16).to_be_bytes())?;
    stream.write_all(&bytes)?;
    let mut length = [0; 2];
    stream.read_exact(&mut length)?;
    let length = usize::from(u16::from_be_bytes(length));
    if !(12..=MAX_MESSAGE).contains(&length) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0; length];
    // Absolute deadline, even if an upstream drip-feeds a response.
    let mut offset = 0;
    while offset < length {
        stream.set_read_timeout(Some(timeout(deadline)?))?;
        let count = stream.read(&mut bytes[offset..])?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        offset += count;
    }
    let mut reply = Message::from_vec(&bytes).map_err(io::Error::other)?;
    if reply.metadata.message_type != MessageType::Response
        || reply.metadata.id != wire.metadata.id
        || reply.metadata.op_code != wire.metadata.op_code
        || reply.queries != wire.queries
        || reply.metadata.truncation
        || reply.signature.is_some()
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    reply.metadata.id = query.metadata.id;
    // This forwarder does not perform DNSSEC validation itself.
    reply.metadata.authentic_data = false;
    Ok(reply)
}
