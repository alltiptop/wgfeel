//! Create the local identity used to enroll a child.
use std::{ffi::OsString, path::Path};
use wgfeel_core::{Config, GatewayAssignment, ManagementConfig, NodeId, Policy};
use wgfeel_store::{LocalTenants, Store};

const USAGE: &str = "usage: wgfeel init --control child --state-dir ABS --id ID";

pub fn run(args: &[OsString]) -> Result<(), &'static str> {
    let [first, first_value, second, second_value] = args else {
        return Err(USAGE);
    };
    let (state, id) = match (first.to_str(), second.to_str()) {
        (Some("--state-dir"), Some("--id")) => (first_value, second_value),
        (Some("--id"), Some("--state-dir")) => (second_value, first_value),
        _ => return Err(USAGE),
    };
    let path = Path::new(state);
    if !path.is_absolute() {
        return Err("Node state path must be absolute");
    }
    let id = NodeId::new(id.to_str().ok_or(USAGE)?).map_err(|_| USAGE)?;
    initialize_unbound(path, id)
}

pub fn generated_id() -> Result<NodeId, &'static str> {
    let mut bytes = [0; 16];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_| "cannot generate node ID")?;
    bytes[6] = (bytes[6] & 15) | 0x40;
    bytes[8] = (bytes[8] & 63) | 0x80;
    let mut id = String::with_capacity(36);
    use std::fmt::Write;
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            id.push('-');
        }
        let _ = write!(id, "{byte:02x}");
    }
    NodeId::new(&id).map_err(|_| "invalid generated node ID")
}
pub fn initialize_unbound(path: &Path, id: NodeId) -> Result<(), &'static str> {
    if path.exists() {
        crate::validate_private_parent(&path.join("state.json"))?;
    } else {
        crate::validate_private_parent(path)?;
    }
    let mut store = Store::initialize(path).map_err(|_| "cannot initialize node state")?;
    if store
        .load()
        .map_err(|_| "cannot inspect node state")?
        .is_some()
    {
        return Err("node state already exists");
    }
    let (private, public, gateway_public) = crate::generate_node_keys()?;
    let unbound = NodeId::new("unbound").map_err(|_| "invalid unbound identity")?;
    let projection = ManagementConfig::new(
        unbound.clone(),
        Config::new(1, vec![], Policy::new(vec![], vec![], vec![]))
            .map_err(|_| "invalid initial config")?,
        vec![
            GatewayAssignment::new(id.clone(), public, gateway_public, vec![], vec![])
                .map_err(|_| "invalid node identity")?,
        ],
    )
    .and_then(|routing| routing.project_mesh_for(&id))
    .map_err(|_| "invalid initial projection")?;
    store
        .commit_projection(
            &unbound,
            &projection,
            &id,
            &private,
            &LocalTenants::default(),
        )
        .map_err(|_| "node identity commit failed or uncertain")?;
    println!(
        "Node {} initialized. Run the join command issued by main.",
        id.as_str()
    );
    Ok(())
}
