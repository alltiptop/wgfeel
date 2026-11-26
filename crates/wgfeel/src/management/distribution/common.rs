//! Configuration TCP streams use main's independently established service sessions.
//! Queues carry bounded inner packets; only the main loop owns the UDP socket.
use super::*;
use wgfeel_protocol::{Response, http, tcp};

pub(super) struct Packet {
    pub peer: NodeId,
    pub generation: u64,
    pub bytes: Zeroizing<Vec<u8>>,
}

pub(super) fn exchange(
    job: &Job,
    outgoing: &SyncSender<Packet>,
    incoming: &Receiver<Packet>,
    current: &AtomicU64,
) -> Result<Response, &'static str> {
    let mut buffers = tcp::Buffers::new(1).map_err(|_| "cannot allocate delivery buffers")?;
    let encoded = http::encode_request_with_limit(
        Request {
            method: "POST",
            target: "/internal/v1/config",
            authorization: None,
            if_match: None,
            body: &job.projection,
        },
        wgfeel_store::MAX_DELIVERY_BYTES,
    )
    .map_err(|_| "invalid delivery request")?;
    let mut client = tcp::Client::distribution(&mut buffers, remote::seed()?, encoded)
        .map_err(|_| "cannot initialize delivery stream")?;
    let started = Instant::now();
    let mut last_received = started;
    loop {
        if current.load(Ordering::Relaxed) != job.generation {
            return Err("configuration delivery superseded");
        }
        if started.elapsed() >= Duration::from_secs(90)
            || last_received.elapsed() >= tcp::DISTRIBUTION_IDLE_TIMEOUT
        {
            return Err("configuration delivery timed out");
        }
        for packet in incoming.try_iter().take(64) {
            if packet.generation == job.generation
                && packet.peer == *job.node.recipient()
                && client.receive(&packet.bytes).is_ok()
            {
                last_received = Instant::now();
            }
        }
        client
            .poll(started.elapsed())
            .map_err(|_| "delivery stream failed")?;
        while let Some(bytes) = client.take_packet() {
            // Bounded packet loss is handled by TCP retransmission.
            let _ = outgoing.try_send(Packet {
                peer: job.node.recipient().clone(),
                generation: job.generation,
                bytes,
            });
        }
        if let Some(response) = client.take_response() {
            return response.map_err(|_| "invalid delivery response");
        }
        thread::sleep(Duration::from_millis(2));
    }
}
