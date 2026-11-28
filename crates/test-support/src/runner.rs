//! Serial test runner for binaries that also serve as their own worker executable.
use std::{
    ffi::OsString,
    io::{self, Write},
    process::ExitCode,
};

/// Register functions using their Rust names so filters and listings match.
#[macro_export]
macro_rules! worker_tests {
    ($arguments:expr, $($case:ident),+ $(,)?) => {
        $crate::runner::run($arguments, &[$((stringify!($case), $case)),+])
    };
}

#[derive(Default)]
struct Selection<'a> {
    filters: Vec<&'a str>,
    skip: Vec<&'a str>,
    exact: bool,
    list: bool,
    ignored_only: bool,
    terse: bool,
}

impl<'a> Selection<'a> {
    fn parse(arguments: &'a [OsString]) -> Result<Self, &'static str> {
        let mut selection = Self::default();
        let mut args = arguments
            .iter()
            .map(|arg| arg.to_str().ok_or("expected UTF-8 test argument"));
        while let Some(arg) = args.next().transpose()? {
            let (option, value) = arg.split_once('=').unwrap_or((arg, ""));
            match arg {
                "--exact" => selection.exact = true,
                "--list" => selection.list = true,
                "--ignored" => selection.ignored_only = true,
                "--include-ignored" | "--nocapture" | "--no-capture" | "--test" => (),
                "--quiet" | "-q" => selection.terse = true,
                _ if matches!(option, "--skip" | "--format" | "--test-threads") => {
                    let value = if arg == option {
                        args.next()
                            .transpose()?
                            .ok_or("missing test option value")?
                    } else {
                        value
                    };
                    match (option, value) {
                        ("--skip", filter) => selection.skip.push(filter),
                        ("--format", "terse") => selection.terse = true,
                        ("--format", "pretty") => selection.terse = false,
                        // The suites run serially, within any positive concurrency limit.
                        ("--test-threads", limit) => {
                            limit
                                .parse::<std::num::NonZeroUsize>()
                                .map_err(|_| "--test-threads requires a positive integer")?;
                        }
                        _ => return Err("supported test formats are pretty and terse"),
                    }
                }
                _ if arg.starts_with('-') => return Err("unsupported worker test option"),
                _ => selection.filters.push(arg),
            }
        }
        Ok(selection)
    }

    fn includes(&self, name: &str) -> bool {
        let matches = |filter: &&str| {
            if self.exact {
                name == *filter
            } else {
                name.contains(filter)
            }
        };
        // These self-executing suites register only active tests.
        !self.ignored_only
            && (self.filters.is_empty() || self.filters.iter().any(matches))
            && !self.skip.iter().any(matches)
    }
}

type Case = (&'static str, fn());

pub fn run(arguments: &[OsString], cases: &[Case]) -> ExitCode {
    run_to(arguments, cases, io::stdout()).unwrap_or_else(|error| {
        eprintln!("cannot write worker test results: {error}");
        ExitCode::FAILURE
    })
}

fn run_to(arguments: &[OsString], cases: &[Case], mut out: impl Write) -> io::Result<ExitCode> {
    let selection = match Selection::parse(arguments) {
        Ok(selection) => selection,
        Err(error) => {
            eprintln!("{error}");
            return Ok(ExitCode::FAILURE);
        }
    };
    let mut selected = 0;
    let mut failed = 0;
    for &(name, case) in cases {
        if !selection.includes(name) {
            continue;
        }
        selected += 1;
        if selection.list {
            writeln!(out, "{name}: test")?;
        } else if std::panic::catch_unwind(case).is_err() {
            failed += 1;
            writeln!(out, "test {name} ... FAILED")?;
        } else if selection.terse {
            write!(out, ".")?;
        } else {
            writeln!(out, "test {name} ... ok")?;
        }
    }
    if selection.list {
        if !selection.terse {
            writeln!(out, "\n{selected} tests, 0 benchmarks")?;
        }
    } else {
        let passed = selected - failed;
        let filtered = cases.len() - selected;
        writeln!(
            out,
            "\ntest result: {}. {passed} passed; {failed} failed; {filtered} filtered out",
            if failed == 0 { "ok" } else { "FAILED" }
        )?;
    }
    Ok(if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_use_test_names_and_ignore_option_values() {
        let args = ["first", "second", "--skip", "slow", "--test-threads=4"].map(OsString::from);
        let selection = Selection::parse(&args).unwrap();
        assert!(selection.includes("first_worker"));
        assert!(selection.includes("second_worker"));
        assert!(!selection.includes("first_slow_worker"));
        assert!(!selection.includes("worker_4"));
    }

    #[test]
    fn listing_and_filtered_runs_never_execute_the_case() {
        let cases: &[Case] = &[("first_worker", || panic!("unexpected execution"))];
        let mut listing = Vec::new();
        assert_eq!(
            run_to(&["--list".into()], cases, &mut listing).unwrap(),
            ExitCode::SUCCESS
        );
        assert!(
            std::str::from_utf8(&listing)
                .unwrap()
                .lines()
                .any(|line| line == "first_worker: test")
        );
        for args in [
            &["--exact", "first"][..],
            &["--ignored"],
            &["worker", "--skip=first"],
        ] {
            let args = args.iter().map(OsString::from).collect::<Vec<_>>();
            assert_eq!(run(&args, cases), ExitCode::SUCCESS);
        }
        assert_eq!(run(&["--unknown".into()], cases), ExitCode::FAILURE);
    }
}
