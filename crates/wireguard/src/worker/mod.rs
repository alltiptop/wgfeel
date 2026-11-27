//! Fresh-process cryptographic workers with bounded, request-driven IPC.

mod child;
mod local;
mod process;
mod protocol;
mod supervisor;

use crate::{ContextId, DatagramEvent, WireGuardError};
pub use local::{
    DnsSource, EncryptedDatagram, LocalError, LocalEvent, LocalGateway, same_provider_session,
};
use std::{ffi::OsString, fmt, process::ExitCode, time::Duration};
pub use supervisor::WorkerGateway;

#[derive(Debug, Clone, Copy)]
pub struct WorkerOptions {
    pub address_space_bytes: u64,
    pub startup_timeout: Duration,
    pub operation_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    Starting,
    Ready,
    Busy,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerInfo {
    pub context: ContextId,
    pub generation: u64,
    pub pid: u32,
    pub state: WorkerState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId {
    pub context: ContextId,
    pub generation: u64,
    pub sequence: u64,
}

#[derive(Debug)]
pub enum Submission {
    Queued(RequestId),
    Immediate(DatagramEvent),
}

#[derive(Debug)]
pub enum WorkerEvent {
    Ready {
        context: ContextId,
        generation: u64,
    },
    Completed {
        request: RequestId,
        result: Result<Option<DatagramEvent>, WireGuardError>,
    },
    Failed {
        context: ContextId,
        generation: u64,
        reason: WorkerError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerError {
    InvalidConfiguration,
    UnknownContext,
    UnknownPeer,
    NotReady,
    Busy,
    Spawn,
    Io,
    Timeout,
    Protocol,
    SequenceExhausted,
    IndexCollision,
    WireGuard(WireGuardError),
}
impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "worker operation rejected: {self:?}")
    }
}
impl std::error::Error for WorkerError {}

/// Call before threads, application state, logging or credential loading.
/// Returns `None` for ordinary CLI invocations; internal mode never falls back.
pub fn worker_main(args: &[OsString]) -> Option<ExitCode> {
    if args.first().is_none_or(|arg| arg != "__wgfeel-worker-v1") {
        return None;
    }
    Some(
        worker_args(args).map_or(ExitCode::FAILURE, |(context, memory)| {
            child::run(&context, memory)
        }),
    )
}

fn worker_args(args: &[OsString]) -> Option<(ContextId, u64)> {
    if args.len() != 3 {
        return None;
    }
    let context = args[1].to_str()?;
    let context = if context == "service" {
        ContextId::Service
    } else if context == "gateway" {
        ContextId::Gateway
    } else if let Some(id) = context.strip_prefix("external:") {
        ContextId::External(wgfeel_core::EgressId::new(id).ok()?)
    } else {
        ContextId::Tenant(wgfeel_core::NetworkId::new(context.strip_prefix("tenant:")?).ok()?)
    };
    let memory = args[2].to_str()?.parse().ok()?;
    Some((context, memory))
}
