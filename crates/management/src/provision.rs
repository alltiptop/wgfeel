use super::{AddDevice, ApiError, generated_id, operations::public_key, storage_error};
use aws_lc_rs::{
    agreement::{PrivateKey, X25519},
    encoding::{AsBigEndian, Curve25519SeedBin},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    io::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use wgfeel_core::*;
use wgfeel_store::{ManagementSecrets, StoredManagement};
use zeroize::Zeroizing;

fn key() -> Result<(Zeroizing<[u8; 32]>, DevicePublicKey), ApiError> {
    let key = PrivateKey::generate(&X25519).map_err(|_| ApiError(503, "key_generation_failed"))?;
    let public = key
        .compute_public_key()
        .map_err(|_| ApiError(503, "key_generation_failed"))?;
    let bytes: Curve25519SeedBin<'_> = key
        .as_be_bytes()
        .map_err(|_| ApiError(503, "key_generation_failed"))?;
    Ok((
        Zeroizing::new(
            bytes
                .as_ref()
                .try_into()
                .map_err(|_| ApiError(503, "key_generation_failed"))?,
        ),
        DevicePublicKey::new(
            public
                .as_ref()
                .try_into()
                .map_err(|_| ApiError(503, "key_generation_failed"))?,
        )?,
    ))
}
fn derive(key: &[u8; 32]) -> Result<DevicePublicKey, ApiError> {
    let public = PrivateKey::from_private_key(&X25519, key)
        .map_err(|_| ApiError(503, "invalid_private_material"))?
        .compute_public_key()
        .map_err(|_| ApiError(503, "invalid_private_material"))?;
    Ok(DevicePublicKey::new(
        public
            .as_ref()
            .try_into()
            .map_err(|_| ApiError(503, "invalid_private_material"))?,
    )?)
}
fn eligible<'a>(
    document: &'a ManagementDocument,
    network: &NetworkId,
) -> impl Iterator<Item = (&'a GatewayAssignment, &'a DevicePublicKey)> {
    document
        .routing()
        .assignments()
        .iter()
        .filter(|node| node.traffic().accepts_devices() && node.endpoint().is_some())
        .filter_map(move |node| {
            node.tenants()
                .iter()
                .find(|tenant| tenant.network() == network)
                .map(|tenant| (node, tenant.public_key()))
        })
}
pub(super) fn device(
    document: &ManagementDocument,
    secrets: &mut ManagementSecrets,
    user: &str,
    value: AddDevice,
) -> Result<(ManagementChange, String), ApiError> {
    let client = ClientId::new(user)?;
    let owner = document
        .clients()
        .iter()
        .find(|owner| owner.id() == &client)
        .ok_or(ApiError(404, "not_found"))?;
    let id = generated_id(None)?;
    let device_id = DeviceId::new(&id)?;
    if owner
        .devices()
        .iter()
        .any(|device| device.id() == &device_id)
    {
        return Err(ApiError(409, "already_exists"));
    }
    let network = owner.network();
    let registrations = document
        .routing()
        .config()
        .networks()
        .iter()
        .find(|entry| entry.id() == network)
        .ok_or(ApiError(422, "invalid_change"))?;
    let mut gateways = eligible(document, network).map(|(node, _)| node);
    let gateway = if let Some(id) = value.gateway {
        let id = NodeId::new(&id)?;
        Some(
            gateways
                .find(|node| node.recipient() == &id)
                .ok_or(ApiError(422, "gateway_not_assigned"))?
                .recipient()
                .clone(),
        )
    } else {
        gateways
            .min_by_key(|node| {
                document
                    .routing()
                    .config()
                    .networks()
                    .iter()
                    .flat_map(|network| network.devices())
                    .filter(|device| device.gateway() == Some(node.recipient()))
                    .count()
            })
            .map(|node| node.recipient().clone())
    };
    let (public, private) = match value.public_key {
        Some(public) => (public_key(&public)?, None),
        None => {
            if gateway.is_none() {
                return Err(ApiError(422, "gateway_required"));
            }
            let (private, public) = key()?;
            (public, Some(DevicePrivateKey::new(*private)?))
        }
    };
    let addresses = if value.addresses.is_empty() {
        (2..=MAX_DEVICES as u16 + 2)
            .find_map(|host| {
                let addresses = vec![
                    IpAddr::V4(Ipv4Addr::new(10, 203, (host >> 8) as u8, host as u8)),
                    IpAddr::V6(Ipv6Addr::new(0xfd77, 0x77, 0, 0, 0, 0, 0, host)),
                ];
                (!registrations
                    .devices()
                    .iter()
                    .any(|device| device.addresses().iter().any(|ip| addresses.contains(ip))))
                .then_some(addresses)
            })
            .ok_or(ApiError(422, "address_pool_exhausted"))?
    } else {
        value.addresses
    };
    let hostname = hostname(&value.name, registrations)?;
    let device = Device::new(device_id.clone(), public, addresses)?
        .with_gateway(gateway)
        .with_hostname(Some(hostname))?;
    if let Some(private) = private {
        secrets
            .insert_device(client.clone(), device_id, private)
            .map_err(storage_error)?;
    }
    Ok((
        ManagementChange::AddDevice {
            client,
            network: network.clone(),
            device,
            metadata: DeviceMetadata::new(Some(value.name), value.description)?,
        },
        id,
    ))
}

fn hostname(name: &str, network: &Network) -> Result<String, ApiError> {
    let label: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(48)
        .collect();
    let base = label.trim_matches('-');
    let base = if base.is_empty() { "device" } else { base };
    for index in 1..=MAX_DEVICES + 1 {
        let name = if index == 1 {
            base.to_owned()
        } else {
            format!("{base}-{index}")
        };
        if !network
            .devices()
            .iter()
            .any(|d| d.hostname() == Some(name.as_str()))
        {
            return Ok(name);
        }
    }
    Err(ApiError(422, "hostname_pool_exhausted"))
}

pub(super) fn reconcile(
    document: ManagementDocument,
    change: &ManagementChange,
    secrets: &mut ManagementSecrets,
) -> Result<ManagementDocument, ApiError> {
    let mut networks = document.routing().config().networks().to_vec();
    if let ManagementChange::AddClient { network, .. } = change {
        for entry in &mut networks {
            if entry.id() == network {
                *entry = entry.clone().with_private_lan(true);
            }
        }
    }
    let mut assignments = document.routing().assignments().to_vec();
    for node in &mut assignments {
        if !node.auto_networks() {
            continue;
        }
        let scope: Vec<_> = networks
            .iter()
            .filter(|network| node.traffic().carries_user_traffic() && network.private_lan())
            .map(|network| network.id().clone())
            .collect();
        let mut tenants = Vec::with_capacity(scope.len());
        for network in &scope {
            if !node.traffic().accepts_devices() {
                continue;
            }
            let public = if let Some(key) = secrets.tenant(node.recipient(), network) {
                derive(key.expose_bytes())?
            } else {
                let (key, public) = key()?;
                secrets
                    .insert_tenant(
                        node.recipient().clone(),
                        network.clone(),
                        TenantPrivateKey::new(*key)?,
                    )
                    .map_err(storage_error)?;
                public
            };
            tenants.push(TenantKeyAssignment::new(network.clone(), public));
        }
        *node = node.with_scope(scope, tenants)?;
    }
    // Removing a home Gateway updates future exports. Native clients must
    // import that changed endpoint/key; mesh transit failover is independent.
    for network in &mut networks {
        let devices = network
            .devices()
            .iter()
            .map(|device| {
                if device.gateway().is_some_and(|id| {
                    !assignments
                        .iter()
                        .any(|node| node.recipient() == id && node.traffic().accepts_devices())
                }) {
                    let replacement = assignments.iter().find(|node| {
                        node.traffic().accepts_devices()
                            && node.endpoint().is_some()
                            && node
                                .tenants()
                                .iter()
                                .any(|tenant| tenant.network() == network.id())
                    });
                    if let Some(node) = replacement {
                        return device.clone().with_gateway(Some(node.recipient().clone()));
                    }
                }
                device.clone()
            })
            .collect();
        *network = network.with_devices(devices)?;
    }
    let routing = ManagementConfig::new(
        document.routing().management_id().clone(),
        document.routing().config().with_networks(networks)?,
        assignments,
    )?;
    let document = ManagementDocument::new(routing, document.clients().to_vec())?;
    secrets.retain_document(&document);
    Ok(document)
}

pub(super) fn export(
    state: &StoredManagement,
    user: &str,
    device: &str,
    network: Option<&str>,
) -> Result<Vec<u8>, ApiError> {
    let user = ClientId::new(user)?;
    let device = DeviceId::new(device)?;
    let network = network.map(NetworkId::new).transpose()?;
    let selected = state
        .document()
        .select_device(&user, &device, network.as_ref())
        .map_err(|error| match error {
            DeviceLookupError::UnknownDevice | DeviceLookupError::InvalidNetwork => {
                ApiError(404, "not_found")
            }
            DeviceLookupError::UnassignedDevice => ApiError(409, "device_unassigned"),
            DeviceLookupError::AmbiguousNetwork => ApiError(500, "invalid_user_context"),
        })?;
    let key = state
        .secrets()
        .device(&user, &device)
        .ok_or(ApiError(409, "device_key_is_external"))?;
    if derive(key.expose_bytes())? != *selected.registration.public_key() {
        return Err(ApiError(503, "device_key_mismatch"));
    }
    let home = selected
        .registration
        .gateway()
        .ok_or(ApiError(409, "gateway_required"))?;
    let gateways = || eligible(state.document(), selected.network.id());
    let (gateway, public) = gateways()
        .find(|(node, _)| node.recipient() == home)
        .ok_or(ApiError(409, "gateway_unavailable"))?;
    let mut output = Vec::new();
    writeln!(
        output,
        "# User: {} ({})\n# Device: {} ({})",
        selected.client.name(),
        selected.client.id().as_str(),
        selected
            .device
            .metadata()
            .name()
            .unwrap_or("Unnamed device"),
        selected.device.id().as_str()
    )
    .map_err(|_| ApiError(500, "encoding_failed"))?;
    output.extend_from_slice(b"[Interface]\nPrivateKey = ");
    // Fill this field last so growing the export never leaves a copy of the private key.
    let private_key_field = output.len()..output.len() + 44;
    output.resize(private_key_field.end, 0);
    output.extend_from_slice(b"\nAddress = ");
    for (index, address) in selected.registration.addresses().iter().enumerate() {
        if index != 0 {
            output.extend_from_slice(b", ");
        }
        write!(
            output,
            "{address}/{}",
            if address.is_ipv4() { 32 } else { 128 }
        )
        .map_err(|_| ApiError(500, "encoding_failed"))?;
    }
    let dns = if selected
        .registration
        .addresses()
        .iter()
        .any(IpAddr::is_ipv4)
    {
        IpAddr::V4(DNS_IPV4)
    } else {
        IpAddr::V6(DNS_IPV6)
    };
    write!(output, "\n# Split DNS: {DNS_ZONE} via {dns}\n")
        .map_err(|_| ApiError(500, "encoding_failed"))?;
    if let Some(hostname) = selected.registration.hostname() {
        writeln!(output, "# available at {hostname}.{DNS_ZONE}")
            .map_err(|_| ApiError(500, "encoding_failed"))?;
    }
    output.extend_from_slice(b"MTU = 1280\n");
    write_peer(&mut output, gateway, public).map_err(|_| ApiError(500, "encoding_failed"))?;
    output.extend_from_slice(b"AllowedIPs = 10.203.0.0/16, fd77:77::/64");
    for address in selected
        .network
        .devices()
        .iter()
        .flat_map(|device| device.addresses())
    {
        let covered = match address {
            IpAddr::V4(ip) => ip.octets()[..2] == [10, 203],
            IpAddr::V6(ip) => ip.segments()[..4] == [0xfd77, 0x77, 0, 0],
        };
        if !covered {
            write!(
                output,
                ", {address}/{}",
                if address.is_ipv4() { 32 } else { 128 }
            )
            .map_err(|_| ApiError(500, "encoding_failed"))?;
        }
    }
    output.extend_from_slice(b"\nPersistentKeepalive = 25\n");
    for (node, public) in gateways().filter(|(node, _)| node.recipient() != home) {
        write_peer(&mut output, node, public).map_err(|_| ApiError(500, "encoding_failed"))?;
    }
    STANDARD
        .encode_slice(key.expose_bytes(), &mut output[private_key_field])
        .map_err(|_| ApiError(500, "encoding_failed"))?;
    Ok(output)
}

fn write_peer(
    output: &mut Vec<u8>,
    node: &GatewayAssignment,
    public: &DevicePublicKey,
) -> std::io::Result<()> {
    let id = node.recipient().as_str();
    match node.hostname().filter(|name| *name != id) {
        Some(name) => writeln!(output, "\n# Node: {name} ({id})")?,
        None => writeln!(output, "\n# Node: {id}")?,
    }
    writeln!(output, "[Peer]")?;
    writeln!(output, "PublicKey = {}", STANDARD.encode(public.as_bytes()))?;
    for (ipv4, family) in [(true, "IPv4"), (false, "IPv6")] {
        let endpoints = node.endpoints().iter().filter(|ep| ep.is_ipv4() == ipv4);
        for (index, endpoint) in endpoints.enumerate() {
            if index == 0 {
                writeln!(output, "# {family}")?;
            }
            let prefix = if Some(*endpoint) == node.endpoint() {
                ""
            } else {
                "# "
            };
            writeln!(output, "{prefix}Endpoint = {endpoint}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod dns_names {
    use super::*;
    #[test]
    fn labels_are_stable_safe_and_unique_only_within_the_owner() {
        let empty = Network::new(NetworkId::new("user").unwrap(), vec![]).unwrap();
        assert_eq!(
            hostname("My Laptop", &empty).map_err(|e| e.1).unwrap(),
            "my-laptop"
        );
        assert_eq!(
            hostname("ноутбук", &empty).map_err(|e| e.1).unwrap(),
            "device"
        );
        let device = Device::new(
            DeviceId::new("one").unwrap(),
            DevicePublicKey::new([3; 32]).unwrap(),
            vec!["10.203.0.2".parse().unwrap()],
        )
        .unwrap()
        .with_hostname(Some("pc".into()))
        .unwrap();
        let occupied = empty.with_devices(vec![device]).unwrap();
        assert_eq!(hostname("PC", &occupied).map_err(|e| e.1).unwrap(), "pc-2");
        assert_eq!(hostname("PC", &empty).map_err(|e| e.1).unwrap(), "pc");
    }
}
