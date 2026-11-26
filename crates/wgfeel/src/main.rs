use std::{
    ffi::OsString,
    io::{self, Write},
    process::ExitCode,
};

use wgfeel_host::{install, output, uninstall};
mod instance;
mod management;

fn run(args: Vec<OsString>) -> Result<(), String> {
    if args.first().is_some_and(|arg| arg == "join") {
        return wgfeel_node::join(&args[1..]).map_err(str::to_owned);
    }
    if args.first().is_some_and(|arg| arg == "api") {
        return management::api_settings::run(&args[1..]);
    }
    if management::is_client(&args) {
        return management::client(&args);
    }
    if args.first().is_some_and(|arg| arg == "uninstall") {
        return uninstall::run(&args[1..]);
    }
    if args.first().is_some_and(|arg| arg == "install") {
        return install::run(&args[1..], |args, endpoints| {
            management::bootstrap::initialize(args, Some(endpoints))
        });
    }
    if args.first().is_some_and(|arg| arg == "update") {
        return install::update::run(&args[1..]);
    }
    if args.first().is_some_and(|arg| arg == "state-check") {
        return wgfeel_host::state_check(&args);
    }
    Err("unknown command. Run wgfeel --help".into())
}

fn main() -> ExitCode {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let Some(exit) = wgfeel_wireguard::worker::worker_main(&args) {
        return exit;
    }
    if let Some(result) = wgfeel_host::help::completion::response(&args, management::complete) {
        return match result {
            Ok(text) if io::stdout().lock().write_all(text.as_bytes()).is_ok() => ExitCode::SUCCESS,
            Ok(_) => ExitCode::FAILURE,
            Err(error) => {
                eprintln!("wgfeel: {error}");
                ExitCode::FAILURE
            }
        };
    }
    if let Some(help) = wgfeel_host::help::requested(&args) {
        return if io::stdout().lock().write_all(help.as_bytes()).is_ok() {
            ExitCode::SUCCESS
        } else {
            eprintln!("wgfeel: cannot write help");
            ExitCode::FAILURE
        };
    }
    if args == [OsString::from("--build-info")] {
        println!("wgfeel {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if let Some(command @ ("init" | "serve")) = args.first().and_then(|arg| arg.to_str()) {
        return instance::run(command, &args[1..]);
    }
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wgfeel: {error}");
            ExitCode::FAILURE
        }
    }
}
