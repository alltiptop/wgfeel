//! Read-only installation discovery and ownership checks shared with the updater.
use super::{Directory, OwnedArtifact, Receipt, Result};
use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
};

pub(crate) struct Installed {
    _base: Directory,
    receipt_directory: Directory,
    artifacts: Vec<OwnedArtifact>,
    pub unit: PathBuf,
    state: PathBuf,
    receipt: Receipt,
}
fn present(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err("cannot inspect existing installation".into()),
    }
}
impl Installed {
    pub fn inspect(root: &Path, base: &Path) -> Result<Option<Self>> {
        let base_path = crate::installation_path(root, base)?;
        let home = base_path.join("instance");
        let unit = root.join("etc/systemd/system/wgfeel.service");
        let alias = root.join("usr/local/bin/wgfeel");
        let directory = Directory::open(&base_path, false, false)?;
        let receipt_directory = Directory::open(&home, true, false)?;
        if let Some(directory) = &directory {
            directory.lock()?;
        }
        if let Some(directory) = &receipt_directory {
            directory.lock()?;
        }
        let receipt = receipt_directory
            .as_ref()
            .map(Receipt::read)
            .transpose()?
            .flatten();
        let Some(receipt) = receipt else {
            if present(&home.join("state"))?
                || present(&home.join("config"))?
                || present(&unit)?
                || present(&alias)?
            {
                return Err(
                    "incomplete installation: receipt is missing; existing files were preserved"
                        .into(),
                );
            }
            return Ok(None);
        };
        receipt.validate(&home)?;
        let Some(service) = &receipt.service else {
            return Err("installation was removed but state remains; remove it explicitly before reinstalling".into());
        };
        let state = home.join("state");
        let config = home.join("config");
        if receipt.state_dir != state
            || receipt.config_dir != config
            || service.scope != "service"
            || service.unit.path != unit
        {
            return Err("installation receipt does not match standard installation paths".into());
        }
        let state_directory =
            Directory::open(&state, true, false)?.ok_or("installed state directory is missing")?;
        state_directory
            .check_file("state.json", true)?
            .ok_or("installed state.json is missing")?;
        let config_directory = Directory::open(&config, true, false)?
            .ok_or("installed configuration directory is missing")?;
        let bytes = config_directory
            .read_private("config.json", 16384)?
            .ok_or("installed config.json is missing")?;
        let settings: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "invalid installed service settings")?;
        let control = match settings["control"].as_str() {
            Some(value @ ("main" | "child")) => value,
            _ => return Err("invalid installed control capability".into()),
        };
        if control == "main" {
            config_directory
                .check_file("admin.json", true)?
                .ok_or("installed administrator profile is missing")?;
        }
        let extra = if control == "child" {
            if let Some(ip) = settings["listen_ip"].as_str() {
                let ip: std::net::IpAddr = ip.parse().map_err(|_| "invalid installed listen IP")?;
                format!(" --listen-ip {ip}")
            } else {
                let listen: SocketAddr = settings["listen"]
                    .as_str()
                    .ok_or("missing installed listen address")?
                    .parse()
                    .map_err(|_| "invalid installed listen address")?;
                format!(" --listen {listen}")
            }
        } else {
            String::new()
        };
        let expected = format!(
            "ExecStart={} serve --control {control} --state-dir {}{extra}",
            home.join("bin/wgfeel").display(),
            state.display()
        );
        if service
            .unit
            .contents
            .lines()
            .filter(|line| line.starts_with("ExecStart="))
            .collect::<Vec<_>>()
            != [expected.as_str()]
        {
            return Err("installed service does not execute the owned binary".into());
        }
        let mut artifacts = Vec::new();
        for artifact in receipt.artifacts() {
            if !artifact.path.starts_with(root.join("etc"))
                && !receipt
                    .resources
                    .iter()
                    .any(|resource| resource.path == artifact.path)
            {
                return Err("installed artifact is outside the installation root".into());
            }
            let checked = OwnedArtifact::check(artifact)?;
            if !checked.present() {
                return Err("installed artifact is missing".into());
            }
            artifacts.push(checked);
        }
        Directory::open(&root.join("usr/local/bin"), false, false)?
            .ok_or("installed command directory is missing")?
            .check_alias("wgfeel", &home.join("bin/wgfeel"))?;
        Ok(Some(Self {
            _base: directory.ok_or("installation base is missing")?,
            receipt_directory: receipt_directory
                .ok_or("installation receipt directory is missing")?,
            artifacts,
            unit,
            state,
            receipt,
        }))
    }
    pub fn recheck(&self) -> Result<()> {
        for artifact in &self.artifacts {
            artifact.recheck()?;
        }
        Ok(())
    }
    pub fn resources(&self, root: &Path) -> Result<super::resources::Update<'_>> {
        super::resources::Update::inspect(root, &self.receipt_directory, &self.receipt)
    }
    pub fn lock_state(&self) -> Result<StateLock> {
        let directory = Directory::open(&self.state, true, false)?
            .ok_or("installed state directory disappeared")?;
        directory.lock()?;
        Ok(StateLock {
            _directory: directory,
        })
    }
}
pub(crate) struct StateLock {
    _directory: Directory,
}

#[derive(serde::Deserialize)]
pub struct ChildSettings {
    pub listen_ip: std::net::IpAddr,
    pub addresses: Vec<std::net::IpAddr>,
    pub start_after_join: bool,
}

pub fn child_settings(state: &Path) -> std::result::Result<Option<ChildSettings>, &'static str> {
    if !state.ends_with("instance/state") {
        return Ok(None);
    }
    let path = state.with_file_name("config");
    let Some(dir) =
        Directory::open(&path, true, false).map_err(|_| "unsafe installation configuration")?
    else {
        return Ok(None);
    };
    let Some(bytes) = dir
        .read_private("config.json", 16384)
        .map_err(|_| "cannot read installation configuration")?
    else {
        return Ok(None);
    };
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| "invalid installation configuration")?;
    if value["control"] != "child" || value.get("listen_ip").is_none() {
        return Ok(None);
    }
    serde_json::from_value(value)
        .map(Some)
        .map_err(|_| "invalid installed child settings")
}
