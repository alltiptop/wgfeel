//! Bounded, zeroizing input for provider private configuration.
use super::*;
use std::{
    fs::File,
    io::{self, IsTerminal, Read},
};
use wgfeel_core::MAX_PROFILE_BYTES;
#[derive(Default)]
pub(super) struct Source {
    path: Option<String>,
    stdin: bool,
}
impl Source {
    pub(super) fn parse(opts: &mut Options) -> Result<Self> {
        let path = opts.take("--config-file");
        let stdin = opts.take("--config-stdin").is_some();
        if usize::from(path.is_some()) + usize::from(stdin) + opts.positional.len() > 1 {
            return Err("choose one profile file or --config-stdin");
        }
        Ok(Self {
            path: path.or_else(|| opts.positional.pop()),
            stdin,
        })
    }
    pub(super) fn read(self, ui: &mut Ui<'_>) -> Result<Option<Zeroizing<Vec<u8>>>> {
        if self.stdin {
            let _echo = Echo::disable()?;
            return read_profile(&mut *ui.input).map(Some);
        }
        let path = match self.path {
            Some(path) => path,
            None if ui.terminal => match line(ui.input, ui.out, "WireGuard profile file: ")? {
                Some(path) if !path.is_empty() => path,
                _ => return Ok(None),
            },
            _ => return Err("a profile file or --config-stdin is required"),
        };
        read_profile(File::open(path).map_err(|_| "cannot open WireGuard profile file")?).map(Some)
    }
}

struct Echo(Option<rustix::termios::Termios>);
impl Echo {
    fn disable() -> Result<Self> {
        use rustix::termios::*;
        let stdin = io::stdin();
        if !stdin.is_terminal() {
            return Ok(Self(None));
        }
        let original = tcgetattr(&stdin).map_err(|_| "cannot read terminal settings")?;
        let mut silent = original.clone();
        silent
            .local_modes
            .remove(LocalModes::ECHO | LocalModes::ECHONL);
        tcsetattr(&stdin, OptionalActions::Now, &silent)
            .map_err(|_| "cannot disable terminal echo")?;
        Ok(Self(Some(original)))
    }
}
impl Drop for Echo {
    fn drop(&mut self) {
        if let Some(original) = &self.0 {
            let _ = rustix::termios::tcsetattr(
                io::stdin(),
                rustix::termios::OptionalActions::Now,
                original,
            );
        }
    }
}
pub(super) fn read_profile(mut reader: impl Read) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(vec![0; MAX_PROFILE_BYTES + 1]);
    let mut used = 0;
    while used < bytes.len() {
        match reader.read(&mut bytes[used..]) {
            Ok(0) => break,
            Ok(count) => used += count,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("cannot read WireGuard profile"),
        }
    }
    if used > MAX_PROFILE_BYTES {
        return Err("WireGuard profile exceeds 16 KiB");
    }
    bytes.truncate(used);
    Ok(bytes)
}
