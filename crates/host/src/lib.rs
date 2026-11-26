//! Shared host lifecycle and local provisioning, independent of either service runtime.
use aws_lc_rs::{
    agreement::{PrivateKey, X25519},
    encoding::{AsBigEndian, Curve25519SeedBin},
};
use wgfeel_core::{DevicePublicKey, ServicePrivateKey};
pub mod executable;
pub mod help;
pub mod install;
pub mod node;
pub mod output;
pub mod private_paths;
pub mod uninstall;

/// Interface endpoints, including private networks and tunnels. The wire format
/// requires unicast without host-specific scope; no public-pool or interface-type
/// filtering is applied. Explicit endpoints still take precedence.
pub fn discover_endpoints(port: u16) -> Vec<std::net::SocketAddr> {
    let mut endpoints: Vec<_> = install::addresses::discover()
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, address)| !address.is_loopback())
        .map(|(_, address)| std::net::SocketAddr::new(address, port))
        .filter(|address| wgfeel_core::validate_node_endpoints(&[*address]).is_ok())
        .collect();
    endpoints.sort();
    endpoints.dedup();
    endpoints.truncate(wgfeel_core::MAX_NODE_ENDPOINTS);
    endpoints
}

/// Installed commands discover the instance base even when invoked through PATH.
/// A downloaded binary defaults to /opt/wgfeel and can override it explicitly.
pub fn default_install_dir() -> std::path::PathBuf {
    if let Ok(executable) = std::env::current_exe()
        && executable.file_name().is_some_and(|name| name == "wgfeel")
        && let Some(bin) = executable.parent()
        && bin.file_name().is_some_and(|name| name == "bin")
        && let Some(home) = bin.parent()
        && home.file_name().is_some_and(|name| name == "instance")
        && let Some(base) = home.parent()
    {
        return base.to_path_buf();
    }
    "/opt/wgfeel".into()
}

pub(crate) fn installation_path(
    root: &std::path::Path,
    base: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    let text = base.to_str().ok_or("invalid installation directory")?;
    if !base.is_absolute()
        || base.parent().is_none()
        || base
            .components()
            .collect::<std::path::PathBuf>()
            .as_os_str()
            != base.as_os_str()
        || text.split('/').any(|part| part == "." || part == "..")
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
    {
        return Err("installation directory must be an absolute normalized path using ASCII letters, digits, / . _ -".into());
    }
    Ok(root.join(
        base.strip_prefix("/")
            .map_err(|_| "invalid installation directory")?,
    ))
}

pub fn validate_private_parent(path: &std::path::Path) -> Result<(), &'static str> {
    private_paths::parent(path).map(|_| ())
}
pub fn generate_service_key() -> Result<(ServicePrivateKey, DevicePublicKey), &'static str> {
    let key = PrivateKey::generate(&X25519).map_err(|_| "cannot generate WireGuard key")?;
    let public = key
        .compute_public_key()
        .map_err(|_| "cannot derive WireGuard public key")?;
    // The provider-owned encoding zeroizes on drop; all retained copies use the
    // domain's redacted, zeroizing secret wrapper.
    let encoded: Curve25519SeedBin<'static> = key
        .as_be_bytes()
        .map_err(|_| "cannot export generated WireGuard key")?;
    let private = ServicePrivateKey::new(
        encoded
            .as_ref()
            .try_into()
            .map_err(|_| "invalid generated WireGuard key")?,
    )
    .map_err(|_| "invalid generated WireGuard key")?;
    let public = DevicePublicKey::new(
        public
            .as_ref()
            .try_into()
            .map_err(|_| "invalid generated WireGuard public key")?,
    )
    .map_err(|_| "invalid generated WireGuard public key")?;
    Ok((private, public))
}

/// Independently generate both permanent application transport identities.
pub fn generate_node_keys()
-> Result<(wgfeel_core::NodeKeys, DevicePublicKey, DevicePublicKey), &'static str> {
    let (service, service_public) = generate_service_key()?;
    let (gateway, gateway_public) = generate_service_key()?;
    if service_public == gateway_public {
        return Err("generated node identities must be distinct");
    }
    let keys = wgfeel_core::NodeKeys::new(
        service,
        wgfeel_core::GatewayPrivateKey::new(*gateway.expose_bytes())
            .map_err(|_| "invalid generated gateway key")?,
    )
    .map_err(|_| "invalid generated node identities")?;
    Ok((keys, service_public, gateway_public))
}

pub fn random_seed() -> Result<u64, &'static str> {
    let mut bytes = [0; 8];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_| "cannot initialize randomness")?;
    Ok(u64::from_le_bytes(bytes))
}

use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
};
use wgfeel_store::Store;
pub fn state_check(args: &[OsString]) -> Result<(), String> {
    if args.len() != 3 || args[0] != "state-check" || args[1] != "--state-dir" {
        return Err("usage: wgfeel state-check --state-dir PATH".into());
    }
    let store = Store::open(&PathBuf::from(&args[2])).map_err(|e| e.to_string())?;
    let state = store
        .load()
        .map_err(|e| e.to_string())?
        .ok_or("no committed state")?;
    let projection = state.projection();
    let output = serde_json::json!({
        "control": wgfeel_core::ControlMode::Child,
        "management_id": projection.management_id().as_str(),
        "scope_networks": projection.assignment().networks().len(),
        "local_contexts": state.local_tenants().len(),
        "generation": state.config().generation(),
        "node_id": state.node_id().as_str(),
        "networks": state.config().networks().len(),
        "devices": state.config().networks().iter().map(|n| n.devices().len()).sum::<usize>(),
    });
    let mut stdout = io::stdout().lock();
    let text = output::render("Local state", &output);
    stdout
        .write_all(text.as_bytes())
        .map_err(|_| "cannot write public summary")?;
    Ok(())
}
