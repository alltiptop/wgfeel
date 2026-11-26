//! One owned child and bounded, nonblocking pipe framing.
use super::{WorkerError, protocol::MAX_FRAME_BYTES};
use crate::ContextId;
use rustix::{
    event::{PollFd, PollFlags},
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
};
use std::{
    io::{ErrorKind, Read, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};
use zeroize::Zeroizing;

const IO_BYTES: usize = 16 * 1024;
const IO_CALLS: usize = 32;

#[cfg(test)]
#[path = "process_tests.rs"]
mod tests;

pub(super) struct Process {
    child: Child,
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
    pipe: Pipe,
}

struct Pipe {
    tx: Zeroizing<Vec<u8>>,
    written: usize,
    header: [u8; 4],
    header_read: usize,
    body: Zeroizing<Vec<u8>>,
    body_read: usize,
}

impl Process {
    pub fn spawn(context: &ContextId, memory: u64) -> Result<Self, WorkerError> {
        let executable = std::env::current_exe().map_err(|_| WorkerError::Spawn)?;
        let context = match context {
            ContextId::Gateway => "gateway".to_owned(),
            ContextId::Service => "service".to_owned(),
            ContextId::Tenant(id) => format!("tenant:{}", id.as_str()),
        };
        let child = Command::new(executable)
            .args(["__wgfeel-worker-v1", &context, &memory.to_string()])
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| WorkerError::Spawn)?;
        // Own the child before any subsequent fallible descriptor setup.
        let mut process = Self {
            child,
            input: None,
            output: None,
            pipe: Pipe::new(),
        };
        process.input = process.child.stdin.take();
        process.output = process.child.stdout.take();
        let input = process.input.as_ref().ok_or(WorkerError::Spawn)?;
        let output = process.output.as_ref().ok_or(WorkerError::Spawn)?;
        fcntl_setfl(
            input,
            fcntl_getfl(input).map_err(|_| WorkerError::Io)? | OFlags::NONBLOCK,
        )
        .map_err(|_| WorkerError::Io)?;
        fcntl_setfl(
            output,
            fcntl_getfl(output).map_err(|_| WorkerError::Io)? | OFlags::NONBLOCK,
        )
        .map_err(|_| WorkerError::Io)?;
        Ok(process)
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }
    pub fn queue(&mut self, frame: Zeroizing<Vec<u8>>) -> Result<(), WorkerError> {
        self.pipe.queue(frame)
    }
    pub fn pending_write(&self) -> bool {
        self.pipe.pending_write()
    }
    pub fn has_complete_buffered_frame(&self) -> bool {
        self.pipe.has_complete_buffered_frame()
    }

    /// Readiness only: never expose descriptors outside the private worker
    /// module and never consume a frame or change the process state here.
    pub fn append_poll_fds<'a>(
        &'a self,
        descriptors: &mut Vec<PollFd<'a>>,
    ) -> Result<(), WorkerError> {
        let output = self.output.as_ref().ok_or(WorkerError::Io)?;
        descriptors.push(PollFd::new(output, PollFlags::IN));
        // An idle pipe is normally writable. Including it would turn the
        // foreground loop into a permanent busy poll even without any work.
        if self.pipe.pending_write() {
            let input = self.input.as_ref().ok_or(WorkerError::Io)?;
            descriptors.push(PollFd::new(input, PollFlags::OUT));
        }
        Ok(())
    }

    /// No frame is legal between requests. Detect the first unsolicited byte
    /// without retaining a partial frame or waiting for an idle deadline.
    pub fn ensure_quiet(&mut self) -> Result<(), WorkerError> {
        if self
            .child
            .try_wait()
            .map_err(|_| WorkerError::Io)?
            .is_some()
        {
            return Err(WorkerError::Io);
        }
        let output = self.output.as_mut().ok_or(WorkerError::Io)?;
        for _ in 0..IO_CALLS {
            match output.read(&mut [0]) {
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Ok(0) => return Err(WorkerError::Io),
                _ => return Err(WorkerError::Protocol),
            }
        }
        // An interrupted probe consumes its budget; the next poll retries.
        Ok(())
    }

    /// At most IO_CALLS syscalls and IO_BYTES per direction. Never wait for a
    /// child or accumulate a second complete reply.
    pub fn poll(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, WorkerError> {
        if self
            .child
            .try_wait()
            .map_err(|_| WorkerError::Io)?
            .is_some()
        {
            return Err(WorkerError::Io);
        }
        let input = self.input.as_mut().ok_or(WorkerError::Io)?;
        let output = self.output.as_mut().ok_or(WorkerError::Io)?;
        self.pipe.poll(input, output)
    }
}

impl Pipe {
    fn new() -> Self {
        Self {
            tx: Zeroizing::new(Vec::new()),
            written: 0,
            header: [0; 4],
            header_read: 0,
            body: Zeroizing::new(Vec::new()),
            body_read: 0,
        }
    }
    fn queue(&mut self, frame: Zeroizing<Vec<u8>>) -> Result<(), WorkerError> {
        if !self.tx.is_empty() || frame.len() > MAX_FRAME_BYTES + 4 {
            return Err(WorkerError::Protocol);
        }
        self.tx = frame;
        self.written = 0;
        Ok(())
    }
    fn pending_write(&self) -> bool {
        !self.tx.is_empty()
    }

    fn has_complete_buffered_frame(&self) -> bool {
        self.header_read == self.header.len() && self.body_read == self.body.len()
    }

    /// At most IO_CALLS syscalls and IO_BYTES per direction. Never wait for a
    /// child or accumulate a second complete reply.
    fn poll(
        &mut self,
        input: &mut impl Write,
        output: &mut impl Read,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, WorkerError> {
        let mut budget = IO_BYTES;
        for _ in 0..IO_CALLS {
            if self.tx.is_empty() || budget == 0 {
                break;
            }
            let end = self.tx.len().min(self.written + budget);
            match input.write(&self.tx[self.written..end]) {
                Ok(0) => return Err(WorkerError::Io),
                Ok(count) => {
                    self.written += count;
                    budget -= count;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return Err(WorkerError::Io),
            }
            if self.written == self.tx.len() {
                self.tx = Zeroizing::new(Vec::new());
                self.written = 0;
            }
        }
        budget = IO_BYTES;
        for _ in 0..IO_CALLS {
            if budget == 0 {
                break;
            }
            if self.header_read == 4 && self.body_read == self.body.len() {
                // A conforming child waits for the next request. Reject any
                // already available trailing byte before accepting this reply.
                let mut extra = [0];
                match output.read(&mut extra) {
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    _ => return Err(WorkerError::Protocol),
                }
                self.header_read = 0;
                self.body_read = 0;
                return Ok(Some(std::mem::replace(
                    &mut self.body,
                    Zeroizing::new(Vec::new()),
                )));
            }
            let target = if self.header_read < 4 {
                &mut self.header[self.header_read..]
            } else {
                let end = self.body.len().min(self.body_read + budget);
                &mut self.body[self.body_read..end]
            };
            match output.read(target) {
                Ok(0) => return Err(WorkerError::Io),
                Ok(count) => {
                    budget -= count;
                    if self.header_read < 4 {
                        self.header_read += count;
                        if self.header_read == 4 {
                            let length = u32::from_le_bytes(self.header) as usize;
                            if !(2..=MAX_FRAME_BYTES).contains(&length) {
                                return Err(WorkerError::Protocol);
                            }
                            self.body = Zeroizing::new(vec![0; length]);
                        }
                    } else {
                        self.body_read += count;
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return Err(WorkerError::Io),
            }
        }
        Ok(None)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
