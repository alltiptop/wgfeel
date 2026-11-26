use super::protocol::{self, Binding, Operation, Output, ProtocolError, Reply};
use crate::{ContextId, Event, Gateway, PeerId, WireGuardError, framing};
use gotatun::packet::Packet;
use std::{
    io::{self, Read, Write},
    process::ExitCode,
};
use wgfeel_sandbox::{WorkerLimits, enter_worker};

pub(super) fn run(context: &ContextId, memory: u64) -> ExitCode {
    // Install this before confinement and before announcing readiness. Linux
    // associates the signal with the thread that spawned this child; that
    // thread must outlive its workers. Recheck the parent to close the race
    // where it exits between observing its PID and installing the signal.
    let Some(parent) = rustix::process::getppid() else {
        return ExitCode::FAILURE;
    };
    if rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
        .is_err()
        || rustix::process::getppid() != Some(parent)
    {
        return ExitCode::FAILURE;
    }
    // No bootstrap read, engine, key or application logging before confinement.
    if enter_worker(WorkerLimits {
        address_space_bytes: memory,
    })
    .is_err()
    {
        return ExitCode::FAILURE;
    }
    match serve(context) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

fn serve(context: &ContextId) -> Result<(), ProtocolError> {
    // std::io::Stdin's internal BufReader can retain bootstrap private bytes
    // outside our Zeroizing frame. Direct safe fd I/O makes no such copy.
    let mut reader = PipeReader;
    let mut writer = PipeWriter;
    write_frame(&mut writer, &protocol::encode_ready())?;
    let (config, limits) = {
        let bootstrap = protocol::read_frame(&mut reader)?;
        protocol::decode_bootstrap(&bootstrap, context)?
    };
    let mut peers: Vec<_> = config.peers.iter().map(|peer| peer.id.clone()).collect();
    let mut gateway =
        Gateway::new(vec![config], limits).map_err(|_| ProtocolError::InvalidFrame)?;
    write_frame(
        &mut writer,
        &protocol::encode_reply(&Reply {
            sequence: 0,
            indices: vec![],
            authenticated_peer: None,
            outcome: Ok(None),
        })?,
    )?;
    let mut expected_sequence = 1;
    loop {
        let request = {
            let frame = protocol::read_frame(&mut reader)?;
            protocol::decode_request(&frame)?
        };
        if request.sequence != expected_sequence {
            return Err(ProtocolError::InvalidFrame);
        }
        let mut authenticated_peer = None;
        let outcome = match request.operation {
            Operation::Receive { peer, packet } => {
                let selected = peer.map(|peer| peer_id(&peers, peer)).transpose()?;
                match framing::datagram(&packet) {
                    Err(error) => Err(error),
                    Ok(_) => match Packet::copy_from(packet.as_slice()).try_into_wg() {
                        Err(_) => Err(WireGuardError::InvalidPacket),
                        Ok(packet) => {
                            let received = gateway
                                .receive_admitted(selected, packet)
                                .map_err(|_| ProtocolError::InvalidFrame)?;
                            authenticated_peer = received
                                .authenticated_peer
                                .as_ref()
                                .map(|peer| peer_slot(&peers, peer))
                                .transpose()?;
                            received.outcome
                        }
                    },
                }
            }
            Operation::Initiate { peer } => gateway.initiate(context, peer_id(&peers, peer)?),
            Operation::Send { peer, packet } => gateway
                .send(context, peer_id(&peers, peer)?, &packet)
                .map(Some),
            Operation::Tick { peer } => gateway.tick(context, peer_id(&peers, peer)?),
            Operation::Reset { peer } => gateway
                .reset(context, peer_id(&peers, peer)?)
                .map(|()| None),
            Operation::SetServicePeers { peers: next } => {
                if *context != ContextId::Service {
                    return Err(ProtocolError::InvalidFrame);
                }
                let ids = next.iter().map(|peer| peer.id.clone()).collect();
                gateway.set_service_peers(next).map(|()| {
                    peers = ids;
                    None
                })
            }
        };
        // Include retirements on errors and no-output operations too. Nothing
        // else may mutate the engine until the next sequenced parent request.
        let indices = gateway
            .live_indices()
            .map_err(|_| ProtocolError::InvalidFrame)?
            .into_iter()
            .map(|binding| {
                Ok(Binding {
                    peer: peer_slot(&peers, &binding.peer)?,
                    index: binding.index,
                })
            })
            .collect::<Result<Vec<_>, ProtocolError>>()?;
        let outcome = match outcome {
            Err(error) => Err(error),
            Ok(event) => Ok(event
                .map(|event| output(context, &peers, event))
                .transpose()?),
        };
        write_frame(
            &mut writer,
            &protocol::encode_reply(&Reply {
                sequence: request.sequence,
                indices,
                authenticated_peer,
                outcome,
            })?,
        )?;
        // The next request implicitly acknowledges acceptance of the previous
        // complete snapshot. No autonomous timers, reads or retries run here.
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(ProtocolError::InvalidFrame)?;
    }
}

fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> Result<(), ProtocolError> {
    writer
        .write_all(bytes)
        .and_then(|()| writer.flush())
        .map_err(|_| ProtocolError::Io)
}
struct PipeReader;
impl Read for PipeReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        rustix::io::read(io::stdin(), bytes).map_err(Into::into)
    }
}
struct PipeWriter;
impl Write for PipeWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        rustix::io::write(io::stdout(), bytes).map_err(Into::into)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn peer_id(peers: &[PeerId], slot: u16) -> Result<&PeerId, ProtocolError> {
    peers
        .get(usize::from(slot))
        .ok_or(ProtocolError::InvalidFrame)
}
fn peer_slot(peers: &[PeerId], peer: &PeerId) -> Result<u16, ProtocolError> {
    peers
        .iter()
        .position(|candidate| candidate == peer)
        .and_then(|slot| u16::try_from(slot).ok())
        .ok_or(ProtocolError::InvalidFrame)
}
fn output(context: &ContextId, peers: &[PeerId], event: Event) -> Result<Output, ProtocolError> {
    match event {
        Event::Network {
            context: actual,
            peer,
            mut packet,
        } if &actual == context => Ok(Output::Network {
            peer: peer_slot(peers, &peer)?,
            packet: std::mem::take(&mut packet.0),
        }),
        Event::Plaintext {
            context: actual,
            peer,
            mut packet,
        } if &actual == context => Ok(Output::Plaintext {
            peer: peer_slot(peers, &peer)?,
            packet: std::mem::take(&mut packet.0),
        }),
        _ => Err(ProtocolError::InvalidFrame),
    }
}
