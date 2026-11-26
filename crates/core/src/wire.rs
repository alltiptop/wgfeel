//! Untrusted JSON is decoded into private DTOs, then passed through constructors.
use crate::*;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    schema_version: u64,
    generation: u64,
    networks: Vec<RawNetwork>,
    policy: RawPolicy,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetwork {
    id: String,
    devices: Vec<RawDevice>,
    #[serde(default)]
    private_lan: bool,
    #[serde(default)]
    suspended: bool,
    #[serde(default = "crate::config::default_dns_upstreams")]
    dns_upstreams: Vec<SocketAddr>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDevice {
    id: String,
    public_key: [u8; 32],
    addresses: Vec<IpAddr>,
    #[serde(default)]
    gateway: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEndpoint {
    network: String,
    device: String,
}
impl RawEndpoint {
    fn validate(self) -> Result<Endpoint, DomainError> {
        Ok(Endpoint::new(
            NetworkId::new(&self.network)?,
            DeviceId::new(&self.device)?,
        ))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    source: RawEndpoint,
    destination: RawEndpoint,
    action: Action,
}
impl RawRule {
    fn validate(self) -> Result<Rule, DomainError> {
        Ok(Rule::new(
            self.source.validate()?,
            self.destination.validate()?,
            self.action,
        ))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGrant {
    source: RawEndpoint,
    destination: RawEndpoint,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    global_rules: Vec<RawRule>,
    local_rules: Vec<RawRule>,
    grants: Vec<RawGrant>,
}

impl Config {
    pub fn from_json(input: &str) -> Result<Self, DomainError> {
        if input.len() > MAX_CONFIG_BYTES {
            return Err(DomainError::LimitExceeded);
        }
        let raw: RawConfig = serde_json::from_str(input).map_err(|_| DomainError::InvalidJson)?;
        if raw.schema_version != u64::from(SCHEMA_VERSION) {
            return Err(DomainError::UnsupportedSchemaVersion);
        }
        let networks = raw
            .networks
            .into_iter()
            .map(|n| {
                let devices = n
                    .devices
                    .into_iter()
                    .map(|d| {
                        let gateway = d.gateway.as_deref().map(NodeId::new).transpose()?;
                        Device::new(
                            DeviceId::new(&d.id)?,
                            DevicePublicKey::new(d.public_key)?,
                            d.addresses,
                        )
                        .and_then(|device| device.with_gateway(gateway).with_hostname(d.hostname))
                    })
                    .collect::<Result<_, _>>()?;
                Network::new(NetworkId::new(&n.id)?, devices).and_then(|network| {
                    network
                        .with_private_lan(n.private_lan)
                        .with_suspended(n.suspended)
                        .with_dns_upstreams(n.dns_upstreams)
                })
            })
            .collect::<Result<_, _>>()?;
        let global = raw
            .policy
            .global_rules
            .into_iter()
            .map(RawRule::validate)
            .collect::<Result<_, _>>()?;
        let local = raw
            .policy
            .local_rules
            .into_iter()
            .map(RawRule::validate)
            .collect::<Result<_, _>>()?;
        let grants = raw
            .policy
            .grants
            .into_iter()
            .map(|g| Ok(Grant::new(g.source.validate()?, g.destination.validate()?)))
            .collect::<Result<_, DomainError>>()?;
        Self::new(raw.generation, networks, Policy::new(global, local, grants))
    }
    pub fn to_json(&self) -> Result<String, DomainError> {
        #[derive(Serialize)]
        struct WireConfig<'a> {
            schema_version: u32,
            generation: u64,
            networks: &'a [Network],
            policy: &'a Policy,
        }
        serde_json::to_string(&WireConfig {
            schema_version: SCHEMA_VERSION,
            generation: self.generation,
            networks: &self.networks,
            policy: &self.policy,
        })
        .map_err(|_| DomainError::InvalidJson)
    }
}
