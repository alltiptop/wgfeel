//! Removal is authorized by a protected installation receipt, never by scanning
//! for familiar filenames. Receipts are retained to allow retry and later purge.
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    ffi::OsString,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
};

pub(crate) mod installed;
mod paths;
pub(crate) mod resources;
pub(crate) mod services;
#[cfg(test)]
mod tests;
use paths::{DataDirectory, Directory, OwnedArtifact, OwnedExecutable};
use services::{HostControl, ServiceControl};

const USAGE: &str = "usage: wgfeel uninstall [--install-dir PATH] [--dry-run] [--purge [--confirm wgfeel]]\nDefault base directory: /opt/wgfeel; common installations own instance/. Removes the service, installed executable and command resources. Data is preserved unless --purge is confirmed. --dry-run never changes files or services.";
const MAX_RECEIPT: usize = 65_536;
type Result<T> = std::result::Result<T, String>;

pub(crate) const RECEIPT: &str = "install.json";

struct Options {
    install_dir: PathBuf,
    dry_run: bool,
    purge: bool,
    confirmed: bool,
}
impl Options {
    fn parse(args: &[OsString]) -> Result<Self> {
        let mut install_dir = None;
        let mut confirmation = None;
        let mut dry_run = false;
        let mut purge = false;
        let mut args = args.iter();
        while let Some(argument) = args.next() {
            match argument.to_str() {
                Some("--install-dir") if install_dir.is_none() => {
                    install_dir = Some(PathBuf::from(args.next().ok_or(USAGE)?));
                }
                Some("--confirm") if confirmation.is_none() => {
                    confirmation = Some(args.next().and_then(|v| v.to_str()).ok_or(USAGE)?);
                }
                Some("--dry-run") if !dry_run => dry_run = true,
                Some("--purge") if !purge => purge = true,
                _ => return Err(USAGE.into()),
            }
        }
        let base = install_dir.unwrap_or_else(crate::default_install_dir);
        if confirmation.is_some_and(|value| !purge || value != "wgfeel") {
            return Err("--confirm wgfeel requires --purge".into());
        }
        let install_dir = crate::installation_path(Path::new("/"), &base)?.join("instance");
        paths::validate_path(&install_dir)?;
        Ok(Self {
            install_dir,
            dry_run,
            purge,
            confirmed: confirmation.is_some(),
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: PathBuf,
    contents: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Service {
    scope: String,
    unit: Artifact,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Executable {
    directory: PathBuf,
    alias: PathBuf,
}
fn required_option<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    de: D,
) -> std::result::Result<Option<T>, D::Error> {
    Option::deserialize(de)
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u64,
    config_dir: PathBuf,
    state_dir: PathBuf,
    #[serde(deserialize_with = "required_option")]
    executable: Option<Executable>,
    #[serde(deserialize_with = "required_option")]
    service: Option<Service>,
    resources: Vec<Artifact>,
}
impl Receipt {
    fn read(directory: &Directory) -> Result<Option<Self>> {
        let Some(bytes) = directory.read_private(RECEIPT, MAX_RECEIPT)? else {
            return Ok(None);
        };
        let receipt: Self =
            serde_json::from_slice(&bytes).map_err(|_| "invalid installation receipt")?;
        if receipt.version != 1 {
            return Err("unsupported installation receipt version".into());
        }
        Ok(Some(receipt))
    }
    fn artifacts(&self) -> Vec<&Artifact> {
        self.service
            .iter()
            .map(|service| &service.unit)
            .chain(&self.resources)
            .collect()
    }
    fn paths(&self) -> Vec<&Path> {
        [&self.config_dir, &self.state_dir]
            .into_iter()
            .map(PathBuf::as_path)
            .chain(
                self.artifacts()
                    .into_iter()
                    .map(|artifact| artifact.path.as_path()),
            )
            .collect()
    }
    fn validate(&self, install_dir: &Path) -> Result<()> {
        if !self.resources.is_empty() {
            let unit = &self
                .service
                .as_ref()
                .ok_or("resources require an installed service")?
                .unit
                .path;
            if !unit.ends_with("etc/systemd/system/wgfeel.service") {
                return Err("invalid service path for installed resources".into());
            }
            let root = unit.ancestors().nth(4).ok_or("invalid resource root")?;
            let expected = resources::artifacts(root);
            if self.resources.len() != expected.len()
                || self
                    .resources
                    .iter()
                    .any(|resource| !expected.iter().any(|item| item.path == resource.path))
            {
                return Err("invalid installed resource paths".into());
            }
        }
        if let Some(executable) = &self.executable {
            paths::validate_path(&executable.alias)?;
            if executable.directory != install_dir.join("bin")
                || executable.alias.file_name() != Some("wgfeel".as_ref())
                || paths::overlap(&executable.alias, install_dir)
                || self.paths().iter().any(|path| {
                    paths::overlap(path, &executable.directory)
                        || paths::overlap(path, &executable.alias)
                })
            {
                return Err("invalid installed executable paths".into());
            }
        }
        let paths = self.paths();
        for (i, path) in paths.iter().enumerate() {
            paths::validate_path(path)?;
            if install_dir.starts_with(path)
                || paths::overlap(path, &install_dir.join(RECEIPT))
                || paths[..i].iter().any(|other| paths::overlap(path, other))
            {
                return Err("overlapping installation paths".into());
            }
        }
        for artifact in self.artifacts() {
            if artifact.contents.is_empty()
                || artifact.contents.len() > MAX_RECEIPT
                || artifact.contents.contains('\0')
            {
                return Err("invalid recorded artifact".into());
            }
        }
        if let Some(service) = &self.service {
            if !matches!(service.scope.as_str(), "service" | "user")
                || service.unit.path.file_name() != Some("wgfeel.service".as_ref())
            {
                return Err("invalid recorded service".into());
            }
            // systemctl disable follows Also=; stop propagation may cross units.
            // Installer units must not couple service lifetimes. Runtime drop-ins
            // are independently refused by the service adapter.
            for line in service.unit.contents.lines() {
                if let Some((key, _)) = line.split_once('=')
                    && matches!(
                        key.trim(),
                        "Also"
                            | "Alias"
                            | "PropagatesStopTo"
                            | "StopPropagatedFrom"
                            | "PartOf"
                            | "BindsTo"
                    )
                {
                    return Err("service has unsupported coupled lifecycle settings".into());
                }
            }
        }
        Ok(())
    }
}

struct Prepared {
    _base: Directory,
    // Keep the receipt directory locked across confirmation and removal.
    _receipts: Directory,
    receipt: Receipt,
    artifacts: Vec<OwnedArtifact>,
    config: DataDirectory,
    state: DataDirectory,
    executable: Option<OwnedExecutable>,
}
impl Prepared {
    fn new(options: &Options) -> Result<Self> {
        let base = Directory::open(
            options
                .install_dir
                .parent()
                .ok_or("invalid installation base")?,
            false,
            false,
        )?
        .ok_or("installation base not found")?;
        base.lock()?;
        let receipts = Directory::open(&options.install_dir, false, false)?
            .ok_or("installation directory not found; no files removed")?;
        receipts.lock()?;
        let receipt = Receipt::read(&receipts)?.ok_or(
            "installation receipt not found; unmanaged installations require manual removal",
        )?;
        receipt.validate(&options.install_dir)?;
        let executable = receipt
            .executable
            .as_ref()
            .map(|executable| OwnedExecutable::check(executable, "wgfeel"))
            .transpose()?;
        if options.purge {
            receipts.check_names(&["bin", "config", "state", RECEIPT])?;
        }
        let artifacts = receipt
            .artifacts()
            .into_iter()
            .map(OwnedArtifact::check)
            .collect::<Result<Vec<_>>>()?;
        let config = DataDirectory::check(
            &receipt.config_dir,
            &["config.json", "admin.json"],
            options.purge,
        )?;
        let state = DataDirectory::check(
            &receipt.state_dir,
            &["state.json", ".pending"],
            options.purge,
        )?;
        if config.same_directory(&state) {
            return Err("configuration and state directories alias each other".into());
        }
        // Without a registered service there is nothing to stop before locking.
        // Refuse an independently running foreground Gateway during preflight.
        if !options.dry_run && receipt.service.is_none() {
            config.lock()?;
            state.lock()?;
        }
        Ok(Self {
            _base: base,
            _receipts: receipts,
            receipt,
            artifacts,
            config,
            state,
            executable,
        })
    }
    fn plan(&self, options: &Options) -> serde_json::Value {
        let mut files = self
            .receipt
            .artifacts()
            .into_iter()
            .map(|a| a.path.clone())
            .collect::<Vec<_>>();
        if options.purge {
            files.extend([
                self.receipt.config_dir.join("config.json"),
                self.receipt.config_dir.join("admin.json"),
                self.receipt.state_dir.join("state.json"),
                self.receipt.state_dir.join(".pending"),
                options.install_dir.join(RECEIPT),
            ]);
        }
        if let Some(executable) = &self.receipt.executable {
            files.extend([executable.directory.clone(), executable.alias.clone()]);
        }
        serde_json::json!({
            "dry_run": options.dry_run, "purge": options.purge,
            "service": self.receipt.service.as_ref().map(|_| "wgfeel.service"),
            "remove_files": files,
            "data_directories": [&self.receipt.config_dir, &self.receipt.state_dir],
            "preserve_data": !options.purge,
            "receipt": options.install_dir.join(RECEIPT),
            "downloaded_binary": "preserved",
        })
    }
    fn apply(&mut self, options: &Options, control: &mut impl ServiceControl) -> Result<()> {
        if options.dry_run {
            return Ok(());
        }
        if let Some(service) = &self.receipt.service {
            control.stop_service(
                &service.scope,
                "wgfeel.service",
                &service.unit.path,
                self.artifacts[0].present(),
            )?;
        }
        // A real Gateway holds the same directory flock for its entire lifetime.
        // Take both locks before any file removal, after service shutdown.
        self.config.lock()?;
        self.state.lock()?;
        if options.purge {
            self.config.refresh_after_stop()?;
            self.state.refresh_after_stop()?;
            self._receipts
                .check_names(&["bin", "config", "state", RECEIPT])?;
        }
        for artifact in &self.artifacts {
            artifact.recheck()?;
        }
        if let Some(executable) = &self.executable {
            executable.recheck()?;
        }
        for artifact in &self.artifacts {
            artifact.remove()?;
        }
        if let Some(service) = &self.receipt.service {
            control.reload(&service.scope)?;
        }
        if let Some(executable) = &self.executable {
            executable.remove()?;
        }
        if options.purge {
            self.config.remove()?;
            self.state.remove()?;
            self._receipts.remove_private(RECEIPT)?;
            self._receipts.remove_empty()?;
        } else if self.receipt.service.is_some() || !self.receipt.resources.is_empty() {
            self.receipt.service = None;
            self.receipt.resources.clear();
            self._receipts.replace_private(
                RECEIPT,
                &serde_json::to_vec(&self.receipt)
                    .map_err(|_| "cannot encode installation receipt")?,
            )?;
        }
        Ok(())
    }
}

pub fn run(args: &[OsString]) -> Result<()> {
    if args == [OsString::from("--help")] {
        return writeln!(io::stdout().lock(), "{USAGE}").map_err(|_| "cannot write help".into());
    }
    let options = Options::parse(args)?;
    if Directory::open(&options.install_dir, false, false)?.is_none() {
        println!(
            "No wgfeel installation at {}. No changes made.",
            options.install_dir.display()
        );
        return Ok(());
    }
    let mut prepared = Prepared::new(&options)?;
    if options.purge && !options.dry_run && !options.confirmed && !io::stdin().is_terminal() {
        return Err(format!(
            "purge requires explicit confirmation: --confirm {}",
            "wgfeel"
        ));
    }
    let mut stdout = io::stdout().lock();
    write!(
        stdout,
        "{}",
        crate::output::render("Uninstall", &prepared.plan(&options))
    )
    .and_then(|_| stdout.flush())
    .map_err(|_| "cannot write uninstall plan")?;
    drop(stdout);
    if options.purge && !options.dry_run && !options.confirmed {
        let mut stderr = io::stderr().lock();
        write!(
            stderr,
            "Permanently delete the listed wgfeel data? Type wgfeel: "
        )
        .and_then(|_| stderr.flush())
        .map_err(|_| "cannot write confirmation prompt")?;
        let mut answer = String::new();
        // A bounded read avoids accepting unbounded terminal/paste input.
        for byte in io::stdin().lock().bytes().take(32) {
            let byte = byte.map_err(|_| "cannot read confirmation")?;
            if byte == b'\n' {
                break;
            }
            answer.push(char::from(byte));
        }
        if answer.trim_end_matches('\r') != "wgfeel" {
            return Err("purge was not confirmed; no changes made".into());
        }
    }
    prepared
        .apply(&options, &mut HostControl)
        .map_err(|error| format!("uninstall incomplete: {error}; receipt retained for retry"))
}
