use std::{ffi::OsString, process::ExitCode};
pub(crate) mod api_settings;
pub(crate) mod bootstrap;
mod client;
mod distribution;
mod enrollment;
mod main_transport;
mod paths;
pub(crate) mod profile;
mod remote;
mod rest;
mod server;
mod transport;

pub(super) fn is_client(args: &[OsString]) -> bool {
    matches!(
        args.first().and_then(|arg| arg.to_str()),
        Some("egress" | "user" | "device" | "config" | "node" | "token")
    )
}

pub(super) fn run(args: &[OsString]) -> ExitCode {
    server::run(args)
}

pub(super) fn client(args: &[OsString]) -> Result<(), String> {
    client::run(args).map_err(str::to_owned)
}

pub(super) fn complete(
    request: &wgfeel_host::help::completion::Completion,
) -> Vec<wgfeel_host::help::completion::Candidate> {
    client::completion::complete(request)
}
