//! Explicit capability dispatch; the filename never selects authority.
use std::{ffi::OsString, process::ExitCode};

pub(super) fn run(command: &str, args: &[OsString]) -> ExitCode {
    match dispatch(command, args) {
        Ok(exit) => exit,
        Err(error) => {
            eprintln!("wgfeel: {error}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(command: &str, args: &[OsString]) -> Result<ExitCode, &'static str> {
    let mut control = None;
    let mut forwarded = Vec::with_capacity(args.len());
    let mut arguments = args.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--control" {
            if control.is_some() {
                return Err("duplicate --control option");
            }
            control = Some(
                arguments
                    .next()
                    .and_then(|value| value.to_str())
                    .ok_or("--control requires main or child")?,
            );
        } else {
            forwarded.push(argument.clone());
        }
    }
    match (command, control) {
        ("init", Some("main")) => {
            if !forwarded.iter().any(|argument| argument == "--traffic") {
                forwarded.extend(["--traffic".into(), "entry".into()]);
            }
            crate::management::bootstrap::run(&forwarded)?;
            Ok(ExitCode::SUCCESS)
        }
        ("init", Some("child")) => {
            wgfeel_host::node::run(&forwarded)?;
            Ok(ExitCode::SUCCESS)
        }
        ("serve", Some("main")) => Ok(crate::management::run(&forwarded)),
        ("serve", Some("child")) => Ok(wgfeel_node::serve(&forwarded)),
        _ => Err("specify --control main or --control child"),
    }
}
