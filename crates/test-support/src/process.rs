use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::io::Errno;
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid};
use std::ffi::OsString;
use std::fmt;
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const MAX_CAPTURE: usize = 1024 * 1024;
const POLL_BYTES: usize = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(2);

#[cfg(test)]
mod tests;

/// Direct executable invocation with an explicit, complete environment.
pub struct ProcessSpec {
    executable: PathBuf,
    arguments: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    directory: Option<PathBuf>,
}

impl ProcessSpec {
    pub fn new(
        executable: PathBuf,
        arguments: Vec<OsString>,
        environment: Vec<(OsString, OsString)>,
        directory: Option<PathBuf>,
    ) -> Self {
        Self {
            executable,
            arguments,
            environment,
            directory,
        }
    }
}

impl fmt::Debug for ProcessSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessSpec").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProcessLimits {
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessError {
    Spawn,
    Io,
    Timeout,
    OutputLimit,
    ExitedBeforeReady,
    InvalidLimits,
    InvalidMarker,
    AlreadyFinished,
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Unit variants deliberately retain no command, environment, or captured output.
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ProcessError {}

pub struct CapturedOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl fmt::Debug for CapturedOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedOutput")
            .field("status", &self.status)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .finish()
    }
}

/// Owns the direct child and its process group. No PID-based adoption API exists.
/// Callers must not independently reap its child (including via waitpid(-1)).
pub struct ManagedChild {
    child: Option<Child>,
    completed_status: Option<ExitStatus>,
    pid: Pid,
    stdout_pipe: Option<ChildStdout>,
    stderr_pipe: Option<ChildStderr>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    limits: ProcessLimits,
    readiness_cursor: usize,
}

impl fmt::Debug for ManagedChild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedChild")
            .field("id", &self.id())
            .finish_non_exhaustive()
    }
}

impl ManagedChild {
    pub fn spawn(spec: ProcessSpec, limits: ProcessLimits) -> Result<Self, ProcessError> {
        if !(1..=MAX_CAPTURE).contains(&limits.max_stdout_bytes)
            || !(1..=MAX_CAPTURE).contains(&limits.max_stderr_bytes)
        {
            return Err(ProcessError::InvalidLimits);
        }
        let mut command = Command::new(spec.executable);
        command
            .args(spec.arguments)
            .env_clear()
            .envs(spec.environment)
            .process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(directory) = spec.directory {
            command.current_dir(directory);
        }
        let mut child = command.spawn().map_err(|_| ProcessError::Spawn)?;
        // Linux child PIDs fit i32 and cannot be init. Never pass group 1 to killpg:
        // rustix maps it to kill(-1), which is broader than an owned process group.
        let pid = i32::try_from(child.id())
            .ok()
            .filter(|pid| *pid > 1)
            .and_then(Pid::from_raw);
        let Some(pid) = pid else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProcessError::Io);
        };
        let mut managed = Self {
            stdout_pipe: child.stdout.take(),
            stderr_pipe: child.stderr.take(),
            child: Some(child),
            completed_status: None,
            pid,
            limits,
            stdout: Vec::with_capacity(limits.max_stdout_bytes),
            stderr: Vec::with_capacity(limits.max_stderr_bytes),
            readiness_cursor: 0,
        };
        // Install the Drop guard before any fallible descriptor setup.
        let setup = (|| {
            set_nonblocking(managed.stdout_pipe.as_ref().ok_or(ProcessError::Io)?)?;
            set_nonblocking(managed.stderr_pipe.as_ref().ok_or(ProcessError::Io)?)
        })();
        if let Err(error) = setup {
            let _ = managed.cleanup();
            return Err(error);
        }
        Ok(managed)
    }

    pub fn id(&self) -> u32 {
        self.pid.as_raw_pid() as u32
    }

    /// Consume the next complete stdout line, excluding its newline. Capture
    /// limits and the cursor are shared with exact-marker readiness waits.
    pub fn next_stdout_line(&mut self, timeout: Duration) -> Result<Vec<u8>, ProcessError> {
        self.wait_for_line(None, timeout)
    }

    pub fn wait_for_stdout_line(
        &mut self,
        expected: &[u8],
        timeout: Duration,
    ) -> Result<(), ProcessError> {
        if expected.is_empty()
            || expected.contains(&b'\n')
            || expected.len() > self.limits.max_stdout_bytes
        {
            return self.fail(ProcessError::InvalidMarker);
        }
        self.wait_for_line(Some(expected), timeout).map(|_| ())
    }

    fn wait_for_line(
        &mut self,
        expected: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Vec<u8>, ProcessError> {
        if self.child.is_none() && self.completed_status.is_none() {
            return Err(ProcessError::AlreadyFinished);
        }
        let started = Instant::now();
        loop {
            if let Err(error) = self.pump(POLL_BYTES) {
                return self.fail(error);
            }
            if let Some(line) = self.find_line(expected) {
                return Ok(line);
            }
            if self.completed_status.is_some() {
                return self.fail(ProcessError::ExitedBeforeReady);
            }
            match self.exited() {
                Ok(true) => {
                    // A last write may race the first pipe poll. Drain after group cleanup
                    // before deciding whether the complete marker was ever emitted.
                    self.collect_finished()?;
                    return if let Some(line) = self.find_line(expected) {
                        Ok(line)
                    } else {
                        self.fail(ProcessError::ExitedBeforeReady)
                    };
                }
                Ok(false) => {}
                Err(error) => return self.fail(error),
            }
            if started.elapsed() >= timeout {
                return self.fail(ProcessError::Timeout);
            }
            std::thread::sleep(POLL_INTERVAL.min(timeout.saturating_sub(started.elapsed())));
        }
    }

    pub fn wait(mut self, timeout: Duration) -> Result<CapturedOutput, ProcessError> {
        if self.completed_status.is_some() {
            return self.finish();
        }
        if self.child.is_none() {
            return Err(ProcessError::AlreadyFinished);
        }
        let started = Instant::now();
        loop {
            if let Err(error) = self.pump(POLL_BYTES) {
                return self.fail(error);
            }
            match self.exited() {
                Ok(true) => return self.finish(),
                Ok(false) => {}
                Err(error) => return self.fail(error),
            }
            if started.elapsed() >= timeout {
                return self.fail(ProcessError::Timeout);
            }
            std::thread::sleep(POLL_INTERVAL.min(timeout.saturating_sub(started.elapsed())));
        }
    }

    pub fn terminate(mut self) -> Result<CapturedOutput, ProcessError> {
        self.finish()
    }

    fn find_line(&mut self, expected: Option<&[u8]>) -> Option<Vec<u8>> {
        while let Some(offset) = self.stdout[self.readiness_cursor..]
            .iter()
            .position(|&byte| byte == b'\n')
        {
            let end = self.readiness_cursor + offset;
            let start = self.readiness_cursor;
            let matched = expected.is_none_or(|expected| &self.stdout[start..end] == expected);
            self.readiness_cursor = end + 1;
            if matched {
                return Some(self.stdout[start..end].to_vec());
            }
        }
        None
    }

    fn exited(&self) -> Result<bool, ProcessError> {
        loop {
            match waitid(
                WaitId::Pid(self.pid),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            ) {
                Err(Errno::INTR) => continue,
                result => {
                    return result
                        .map(|status| status.is_some())
                        .map_err(|_| ProcessError::Io);
                }
            }
        }
    }

    fn pump(&mut self, budget: usize) -> Result<(), ProcessError> {
        drain(
            &mut self.stdout_pipe,
            &mut self.stdout,
            self.limits.max_stdout_bytes,
            budget,
        )?;
        drain(
            &mut self.stderr_pipe,
            &mut self.stderr,
            self.limits.max_stderr_bytes,
            budget,
        )
    }

    fn close_pipes(&mut self) {
        self.stdout_pipe.take();
        self.stderr_pipe.take();
    }

    fn fail<T>(&mut self, error: ProcessError) -> Result<T, ProcessError> {
        let _ = self.cleanup();
        self.completed_status = None;
        self.close_pipes();
        Err(error)
    }

    fn collect_finished(&mut self) -> Result<(), ProcessError> {
        let result = self.cleanup();
        let drained = self.pump(MAX_CAPTURE + 1);
        self.close_pipes();
        let status = result?;
        drained?;
        self.completed_status = Some(status);
        Ok(())
    }

    fn finish(&mut self) -> Result<CapturedOutput, ProcessError> {
        if self.completed_status.is_none() {
            self.collect_finished()?;
        }
        let status = self
            .completed_status
            .take()
            .ok_or(ProcessError::AlreadyFinished)?;
        Ok(CapturedOutput {
            status,
            stdout: std::mem::take(&mut self.stdout),
            stderr: std::mem::take(&mut self.stderr),
        })
    }

    fn cleanup(&mut self) -> Result<ExitStatus, ProcessError> {
        let Some(mut child) = self.child.take() else {
            return Err(ProcessError::AlreadyFinished);
        };
        // NOWAIT confirms ownership and keeps the leader PID reserved. If a caller
        // violated exclusive reaping, do not signal a possibly reused PID/PGID.
        if self.exited().is_err() {
            return Err(ProcessError::Io);
        }
        let group_result = match kill_process_group(self.pid, Signal::KILL) {
            Ok(()) | Err(Errno::SRCH) => Ok(()),
            Err(_) => Err(ProcessError::Io),
        };
        // Also covers an ordinary fixture that changed its own group. Escaped
        // descendants remain outside the contract. Leader is still unreaped here.
        let _ = child.kill();
        let status = child.wait().map_err(|_| ProcessError::Io)?;
        group_result?;
        Ok(status)
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.cleanup();
        }
    }
}

fn set_nonblocking(fd: &impl AsFd) -> Result<(), ProcessError> {
    let flags = fcntl_getfl(fd).map_err(|_| ProcessError::Io)?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK).map_err(|_| ProcessError::Io)
}

fn drain<R: Read>(
    pipe: &mut Option<R>,
    capture: &mut Vec<u8>,
    limit: usize,
    mut budget: usize,
) -> Result<(), ProcessError> {
    let Some(reader) = pipe.as_mut() else {
        return Ok(());
    };
    let mut buffer = [0; 4096];
    while budget > 0 {
        let length = buffer.len().min(budget).min(limit - capture.len() + 1);
        match reader.read(&mut buffer[..length]) {
            Ok(0) => {
                pipe.take();
                return Ok(());
            }
            Ok(count) => {
                if count > limit - capture.len() {
                    return Err(ProcessError::OutputLimit);
                }
                capture.extend_from_slice(&buffer[..count]);
                budget -= count;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(_) => return Err(ProcessError::Io),
        }
    }
    Ok(())
}
