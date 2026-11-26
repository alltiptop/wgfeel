//! Shared main/child forwarding library: userspace WireGuard, isolated forwarding and local lifecycle.
//! No dependency on the authoritative Management service or its CLI.
use std::{ffi::OsString, process::ExitCode};
mod join;
mod local;
mod runtime;
pub use runtime::{MainEvent, MainForwarder};

/// Run a child after explicit control-mode selection by the common executable.
/// Its state validation enforces the pinned authority independently.
pub fn serve(args: &[OsString]) -> ExitCode {
    runtime::run(args)
}
pub fn join(args: &[OsString]) -> Result<(), &'static str> {
    join::run(args)
}
