use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use std::{
    io::{self, Read},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const MAX_OUTPUT: usize = 16 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);

pub(super) trait ServiceControl {
    fn stop_service(
        &mut self,
        scope: &str,
        unit: &str,
        path: &Path,
        file_present: bool,
    ) -> Result<(), String>;
    fn reload(&mut self, scope: &str) -> Result<(), String>;
}

pub(crate) struct HostControl;

pub(crate) trait UpdateControl {
    fn active(&mut self, unit: &str, path: &Path) -> Result<bool, String>;
    fn stop(&mut self, unit: &str, path: &Path) -> Result<(), String>;
    fn start(&mut self, unit: &str, path: &Path) -> Result<(), String>;
}

impl UpdateControl for HostControl {
    fn active(&mut self, unit: &str, path: &Path) -> Result<bool, String> {
        update_active(&mut HostExecutor, unit, path)
    }
    fn stop(&mut self, unit: &str, path: &Path) -> Result<(), String> {
        update_action(&mut HostExecutor, "stop", unit, path)
    }
    fn start(&mut self, unit: &str, path: &Path) -> Result<(), String> {
        update_action(&mut HostExecutor, "start", unit, path)
    }
}

fn update_active(executor: &mut impl Executor, unit: &str, path: &Path) -> Result<bool, String> {
    if unit != "wgfeel.service" {
        return Err("unsupported update service".into());
    }
    let state = show(executor, "service", unit)?;
    state.validate_owned(path.to_str().ok_or("invalid unit path")?)?;
    match state.active.as_str() {
        "active" => Ok(true),
        "inactive" | "failed" => Ok(false),
        _ => Err("service is changing state; retry the update when it is stable".into()),
    }
}

fn update_action(
    executor: &mut impl Executor,
    action: &str,
    unit: &str,
    path: &Path,
) -> Result<(), String> {
    update_active(executor, unit, path)?;
    successful(
        systemctl(executor, "service", &[action, "--", unit])?,
        "cannot change service state during update",
    )?;
    let state = show(executor, "service", unit)?;
    state.validate_owned(path.to_str().ok_or("invalid unit path")?)?;
    if state.active
        != if action == "start" {
            "active"
        } else {
            "inactive"
        }
    {
        return Err(
            "service did not reach expected state during update; inspect its journal".into(),
        );
    }
    Ok(())
}

pub(crate) fn install_unit(unit: &str, path: &Path) -> Result<(), String> {
    if unit != "wgfeel.service" {
        return Err("unsupported service name".into());
    }
    let mut executor = HostExecutor;
    reload(&mut executor, "service")?;
    show(&mut executor, "service", unit)?
        .validate_owned(path.to_str().ok_or("invalid unit path")?)?;
    successful(
        systemctl(&mut executor, "service", &["enable", "--now", "--", unit])?,
        "cannot enable and start installed service",
    )?;
    let state = show(&mut executor, "service", unit)?;
    state.validate_owned(path.to_str().ok_or("invalid unit path")?)?;
    if state.active != "active" {
        return Err("installed service is not active; inspect its journal".into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Program {
    Systemctl,
}

struct CommandOutput {
    success: bool,
    stdout: Vec<u8>,
}

trait Executor {
    fn run(&mut self, program: Program, args: &[&str]) -> Result<CommandOutput, String>;
}

struct HostExecutor;

impl Executor for HostExecutor {
    fn run(&mut self, program: Program, args: &[&str]) -> Result<CommandOutput, String> {
        let executable = match program {
            Program::Systemctl => "/usr/bin/systemctl",
        };
        let mut command = Command::new(executable);
        command
            .args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if program == Program::Systemctl && args.first() == Some(&"--user") {
            for name in ["HOME", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
        }
        let started = Instant::now();
        let mut child = OwnedChild(
            command
                .spawn()
                .map_err(|_| "cannot start service command")?,
        );
        let mut stdout = child
            .0
            .stdout
            .take()
            .ok_or("service command has no output pipe")?;
        let flags = fcntl_getfl(&stdout).map_err(|_| "cannot inspect command output pipe")?;
        fcntl_setfl(&stdout, flags | OFlags::NONBLOCK)
            .map_err(|_| "cannot make command output pipe nonblocking")?;
        let mut output = Vec::with_capacity(MAX_OUTPUT);
        let mut buffer = [0; 4096];
        let mut eof = false;
        loop {
            if started.elapsed() >= TIMEOUT {
                return Err("service command timed out; operation may be incomplete".into());
            }
            let mut progress = false;
            if !eof {
                match stdout.read(&mut buffer) {
                    Ok(0) => eof = true,
                    Ok(count) => {
                        if count > MAX_OUTPUT - output.len() {
                            return Err("service command output exceeded limit".into());
                        }
                        output.extend_from_slice(&buffer[..count]);
                        progress = true;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err("cannot read service command output".into()),
                }
            }
            let status = child
                .0
                .try_wait()
                .map_err(|_| "cannot wait for service command")?;
            if let Some(status) = status.filter(|_| eof) {
                return Ok(CommandOutput {
                    success: status.success(),
                    stdout: output,
                });
            }
            if !progress {
                std::thread::sleep(
                    Duration::from_millis(10).min(TIMEOUT.saturating_sub(started.elapsed())),
                );
            }
        }
    }
}

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        // The deadline bounds command work. Reaping after SIGKILL still relies on
        // the kernel completing termination, as with the existing child guards.
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

impl ServiceControl for HostControl {
    fn stop_service(
        &mut self,
        scope: &str,
        unit: &str,
        path: &Path,
        file_present: bool,
    ) -> Result<(), String> {
        stop_service(&mut HostExecutor, scope, unit, path, file_present)
    }

    fn reload(&mut self, scope: &str) -> Result<(), String> {
        reload(&mut HostExecutor, scope)
    }
}

fn stop_service(
    executor: &mut impl Executor,
    scope: &str,
    unit: &str,
    path: &Path,
    file_present: bool,
) -> Result<(), String> {
    if unit != "wgfeel.service" {
        return Err("unsupported service name".into());
    }
    let fragment = path
        .to_str()
        .filter(|_| path.is_absolute())
        .ok_or("invalid service path")?;
    let state = show(executor, scope, unit)?;
    if state.is_absent() && !file_present {
        return Ok(());
    }
    state.validate_owned(fragment)?;
    successful(
        systemctl(executor, scope, &["stop", "--", unit])?,
        "service stop failed",
    )?;
    let stopped = show(executor, scope, unit)?;
    stopped.validate_owned(fragment)?;
    if stopped.active != "inactive" {
        return Err("service stop did not reach inactive state".into());
    }
    successful(
        systemctl(executor, scope, &["--no-reload", "disable", "--", unit])?,
        "service disable failed",
    )?;
    Ok(())
}

fn reload(executor: &mut impl Executor, scope: &str) -> Result<(), String> {
    successful(
        systemctl(executor, scope, &["daemon-reload"])?,
        "service manager reload failed",
    )?;
    Ok(())
}

fn systemctl(
    executor: &mut impl Executor,
    scope: &str,
    tail: &[&str],
) -> Result<CommandOutput, String> {
    let scope = match scope {
        "service" => "--system",
        "user" => "--user",
        _ => return Err("unsupported service scope".into()),
    };
    let mut args = vec![scope, "--no-pager", "--no-ask-password"];
    args.extend(tail);
    executor.run(Program::Systemctl, &args)
}

fn successful(output: CommandOutput, error: &str) -> Result<Vec<u8>, String> {
    if output.success && output.stdout.len() <= MAX_OUTPUT {
        Ok(output.stdout)
    } else {
        Err(error.into())
    }
}

struct UnitState {
    load: String,
    active: String,
    fragment: String,
    drop_ins: String,
}

impl UnitState {
    fn is_absent(&self) -> bool {
        self.load == "not-found"
            && self.active == "inactive"
            && self.fragment.is_empty()
            && self.drop_ins.is_empty()
    }

    fn validate_owned(&self, fragment: &str) -> Result<(), String> {
        if self.load != "loaded" || self.fragment != fragment || !self.drop_ins.is_empty() {
            return Err("service manager unit does not match the installation receipt".into());
        }
        Ok(())
    }
}

fn show(executor: &mut impl Executor, scope: &str, unit: &str) -> Result<UnitState, String> {
    let bytes = successful(
        systemctl(
            executor,
            scope,
            &[
                "show",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=FragmentPath",
                "--property=DropInPaths",
                "--",
                unit,
            ],
        )?,
        "cannot query service manager",
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "invalid service manager response")?;
    let mut values: [Option<&str>; 4] = [None; 4];
    if !text.ends_with('\n') || text.contains('\r') {
        return Err("invalid service manager response".into());
    }
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or("invalid service manager property")?;
        let slot = match key {
            "LoadState" => 0,
            "ActiveState" => 1,
            "FragmentPath" => 2,
            "DropInPaths" => 3,
            _ => return Err("unknown service manager property".into()),
        };
        if values[slot].replace(value).is_some() {
            return Err("duplicate service manager property".into());
        }
    }
    let [Some(load), Some(active), Some(fragment), Some(drop_ins)] = values else {
        return Err("missing service manager property".into());
    };
    if !matches!(
        active,
        "active"
            | "inactive"
            | "failed"
            | "activating"
            | "deactivating"
            | "maintenance"
            | "reloading"
            | "refreshing"
    ) {
        return Err("unknown service active state".into());
    }
    Ok(UnitState {
        load: load.into(),
        active: active.into(),
        fragment: fragment.into(),
        drop_ins: drop_ins.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const UNIT: &str = "wgfeel.service";
    const FILE: &str = "/etc/systemd/system/wgfeel.service";

    struct Step {
        program: Program,
        args: Vec<String>,
        output: Result<CommandOutput, String>,
    }

    #[derive(Default)]
    struct Fake {
        steps: VecDeque<Step>,
    }

    impl Fake {
        fn step(&mut self, program: Program, args: &[&str], success: bool, stdout: &str) {
            self.steps.push_back(Step {
                program,
                args: args.iter().map(|s| (*s).into()).collect(),
                output: Ok(CommandOutput {
                    success,
                    stdout: stdout.as_bytes().to_vec(),
                }),
            });
        }

        fn system(&mut self, scope: &str, tail: &[&str], success: bool, stdout: &str) {
            let mut args = vec![scope, "--no-pager", "--no-ask-password"];
            args.extend(tail);
            self.step(Program::Systemctl, &args, success, stdout);
        }

        fn show(&mut self, stdout: &str) {
            self.show_unit(UNIT, stdout);
        }

        fn show_unit(&mut self, unit: &str, stdout: &str) {
            self.system(
                "--system",
                &[
                    "show",
                    "--property=LoadState",
                    "--property=ActiveState",
                    "--property=FragmentPath",
                    "--property=DropInPaths",
                    "--",
                    unit,
                ],
                true,
                stdout,
            );
        }

        fn done(&self) {
            assert!(self.steps.is_empty(), "expected commands were not executed");
        }
    }

    impl Executor for Fake {
        fn run(&mut self, program: Program, args: &[&str]) -> Result<CommandOutput, String> {
            let step = self.steps.pop_front().expect("unexpected command");
            assert_eq!(program, step.program);
            assert_eq!(args, step.args);
            step.output
        }
    }

    fn loaded(active: &str) -> String {
        format!("LoadState=loaded\nActiveState={active}\nFragmentPath={FILE}\nDropInPaths=\n")
    }

    #[test]
    fn update_stops_and_starts_owned_service_without_changing_enablement() {
        let mut fake = Fake::default();
        fake.show(&loaded("active"));
        assert!(update_active(&mut fake, UNIT, Path::new(FILE)).unwrap());
        for (action, before, after) in [
            ("stop", "active", "inactive"),
            ("start", "inactive", "active"),
        ] {
            fake.show(&loaded(before));
            fake.system("--system", &[action, "--", UNIT], true, "");
            fake.show(&loaded(after));
            update_action(&mut fake, action, UNIT, Path::new(FILE)).unwrap();
        }
        fake.done();
    }

    #[test]
    fn update_refuses_foreign_or_unstable_service_before_actions() {
        for bad in [
            loaded("active").replace(FILE, "/other/wgfeel.service"),
            loaded("active").replace("DropInPaths=", "DropInPaths=/etc/override.conf"),
            loaded("activating"),
            absent().to_owned(),
        ] {
            let mut fake = Fake::default();
            fake.show(&bad);
            assert!(update_action(&mut fake, "stop", UNIT, Path::new(FILE)).is_err());
            fake.done();
        }
    }

    fn absent() -> &'static str {
        "LoadState=not-found\nActiveState=inactive\nFragmentPath=\nDropInPaths=\n"
    }

    #[test]
    fn owned_loaded_service_is_stopped_verified_then_disabled_without_reload() {
        let mut fake = Fake::default();
        fake.show(&loaded("active"));
        fake.system("--system", &["stop", "--", UNIT], true, "");
        fake.show(&loaded("inactive"));
        fake.system(
            "--system",
            &["--no-reload", "disable", "--", UNIT],
            true,
            "",
        );
        assert!(stop_service(&mut fake, "service", UNIT, Path::new(FILE), true).is_ok());
        fake.done();
    }

    #[test]
    fn absent_service_requires_positive_manager_evidence_and_absent_file() {
        let mut fake = Fake::default();
        fake.show(absent());
        assert!(stop_service(&mut fake, "service", UNIT, Path::new(FILE), false).is_ok());
        fake.done();
        let mut fake = Fake::default();
        fake.show(absent());
        assert!(stop_service(&mut fake, "service", UNIT, Path::new(FILE), true).is_err());
        fake.done();
    }

    #[test]
    fn bad_properties_are_rejected_before_stop() {
        let valid = loaded("active");
        for bad in [
            valid.replace(FILE, "/other/wgfeel.service"),
            valid.replace("DropInPaths=", "DropInPaths=/etc/override.conf"),
            valid.replace("loaded", "error"),
            valid.replace("active", "future-state"),
            valid.replace("DropInPaths=\n", ""),
            format!("{valid}LoadState=loaded\n"),
            format!("{valid}Unexpected=value\n"),
            absent().replace("inactive", "active"),
        ] {
            let mut fake = Fake::default();
            fake.show(&bad);
            assert!(stop_service(&mut fake, "service", UNIT, Path::new(FILE), true).is_err());
            fake.done();
        }
    }

    #[test]
    fn stop_failure_or_unconfirmed_stop_cannot_disable() {
        let mut fake = Fake::default();
        fake.show(&loaded("active"));
        fake.system("--system", &["stop", "--", UNIT], false, "");
        assert!(stop_service(&mut fake, "service", UNIT, Path::new(FILE), true).is_err());
        fake.done();
        let mut fake = Fake::default();
        fake.show(&loaded("active"));
        fake.system("--system", &["stop", "--", UNIT], true, "");
        fake.show(&loaded("deactivating"));
        assert!(stop_service(&mut fake, "service", UNIT, Path::new(FILE), true).is_err());
        fake.done();
    }

    #[test]
    fn manager_error_is_not_an_absent_unit() {
        let mut fake = Fake::default();
        fake.show(absent());
        fake.steps
            .front_mut()
            .unwrap()
            .output
            .as_mut()
            .unwrap()
            .success = false;
        assert!(stop_service(&mut fake, "service", UNIT, Path::new(FILE), false).is_err());
        fake.done();
    }

    #[test]
    fn disable_failure_is_not_success() {
        let mut fake = Fake::default();
        fake.show(&loaded("inactive"));
        fake.system("--system", &["stop", "--", UNIT], true, "");
        fake.show(&loaded("inactive"));
        fake.system(
            "--system",
            &["--no-reload", "disable", "--", UNIT],
            false,
            "",
        );
        assert!(stop_service(&mut fake, "service", UNIT, Path::new(FILE), true).is_err());
        fake.done();
    }

    #[test]
    fn reload_is_explicit_scoped_and_failure_is_preserved() {
        for (scope, flag, success) in [("service", "--system", true), ("user", "--user", false)] {
            let mut fake = Fake::default();
            fake.system(flag, &["daemon-reload"], success, "");
            assert_eq!(reload(&mut fake, scope).is_ok(), success);
            fake.done();
        }
    }

    #[test]
    fn arbitrary_names_and_scopes_never_reach_executor() {
        let mut fake = Fake::default();
        for (scope, unit) in [
            ("other", UNIT),
            ("service", "sshd.service"),
            ("service", "--all"),
        ] {
            assert!(stop_service(&mut fake, scope, unit, Path::new(FILE), true).is_err());
        }
        assert!(reload(&mut fake, "other").is_err());
        fake.done();
    }
}
