use crate::{
    DeviceId, DevicePublicKey, DomainError, MAX_DEVICES, MAX_NETWORKS, MAX_POLICY_RULES, NetworkId,
    NodeId,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

pub const DNS_ZONE: &str = "feel.internal";
pub const DNS_IPV4: Ipv4Addr = Ipv4Addr::new(10, 203, 0, 1);
pub const DNS_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd77, 0x77, 0, 0, 0, 0, 0, 1);
pub fn is_dns_address(address: IpAddr) -> bool {
    address == IpAddr::V4(DNS_IPV4) || address == IpAddr::V6(DNS_IPV6)
}
pub(crate) fn default_dns_upstreams() -> Vec<SocketAddr> {
    vec![
        SocketAddr::from(([1, 1, 1, 1], 53)),
        SocketAddr::from(([9, 9, 9, 9], 53)),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Device {
    id: DeviceId,
    public_key: DevicePublicKey,
    addresses: Vec<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway: Option<NodeId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
}
impl Device {
    pub fn new(
        id: DeviceId,
        public_key: DevicePublicKey,
        addresses: Vec<IpAddr>,
    ) -> Result<Self, DomainError> {
        if addresses.is_empty()
            || addresses.len() > 2
            || (addresses.len() == 2 && addresses[0].is_ipv4() == addresses[1].is_ipv4())
        {
            return Err(DomainError::InvalidAddressCount);
        }
        for address in &addresses {
            if is_dns_address(*address)
                || address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || match address {
                    IpAddr::V4(v4) => v4.is_broadcast(),
                    IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some(),
                }
            {
                return Err(DomainError::InvalidAddress);
            }
        }
        Ok(Self {
            id,
            public_key,
            addresses,
            gateway: None,
            hostname: None,
        })
    }
    pub fn id(&self) -> &DeviceId {
        &self.id
    }
    pub fn with_gateway(mut self, gateway: Option<NodeId>) -> Self {
        self.gateway = gateway;
        self
    }
    pub fn gateway(&self) -> Option<&NodeId> {
        self.gateway.as_ref()
    }
    /// A stable, single DNS label, unique within its owner's network.
    pub fn with_hostname(mut self, hostname: Option<String>) -> Result<Self, DomainError> {
        if let Some(name) = &hostname
            && (name.is_empty()
                || name.len() > 63
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                || name.starts_with('-')
                || name.ends_with('-'))
        {
            return Err(DomainError::InvalidHostname);
        }
        self.hostname = hostname;
        Ok(self)
    }
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }
    pub fn public_key(&self) -> &DevicePublicKey {
        &self.public_key
    }
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Network {
    id: NetworkId,
    devices: Vec<Device>,
    #[serde(skip_serializing_if = "is_false")]
    private_lan: bool,
    #[serde(skip_serializing_if = "is_false")]
    suspended: bool,
    dns_upstreams: Vec<SocketAddr>,
}
fn is_false(value: &bool) -> bool {
    !*value
}
impl Network {
    pub fn new(id: NetworkId, devices: Vec<Device>) -> Result<Self, DomainError> {
        if devices.len() > MAX_DEVICES {
            return Err(DomainError::LimitExceeded);
        }
        let (mut ids, mut keys, mut addresses) =
            (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        let mut hostnames = BTreeSet::new();
        for device in &devices {
            if let Some(hostname) = device.hostname()
                && !hostnames.insert(hostname)
            {
                return Err(DomainError::DuplicateHostname);
            }
            if !ids.insert(&device.id) {
                return Err(DomainError::DuplicateDeviceId);
            }
            if !keys.insert(&device.public_key) {
                return Err(DomainError::DuplicateDeviceKey);
            }
            for address in &device.addresses {
                if !addresses.insert(address) {
                    return Err(DomainError::DuplicateDeviceAddress);
                }
            }
        }
        Ok(Self {
            id,
            devices,
            private_lan: false,
            suspended: false,
            dns_upstreams: default_dns_upstreams(),
        })
    }
    pub fn with_private_lan(mut self, enabled: bool) -> Self {
        self.private_lan = enabled;
        self
    }
    pub fn private_lan(&self) -> bool {
        self.private_lan
    }
    pub fn with_suspended(mut self, suspended: bool) -> Self {
        self.suspended = suspended;
        self
    }
    pub fn suspended(&self) -> bool {
        self.suspended
    }
    /// Empty disables external lookup; private names are still served locally.
    pub fn with_dns_upstreams(mut self, upstreams: Vec<SocketAddr>) -> Result<Self, DomainError> {
        if upstreams.len() > 3
            || upstreams.iter().any(|server| {
                server.port() == 0
                    || is_dns_address(server.ip())
                    || server.ip().is_unspecified()
                    || server.ip().is_multicast()
            })
        {
            return Err(DomainError::InvalidDnsUpstream);
        }
        self.dns_upstreams = upstreams;
        Ok(self)
    }
    pub fn dns_upstreams(&self) -> &[SocketAddr] {
        &self.dns_upstreams
    }
    pub fn with_devices(&self, devices: Vec<Device>) -> Result<Self, DomainError> {
        Self::new(self.id.clone(), devices)?
            .with_private_lan(self.private_lan)
            .with_suspended(self.suspended)
            .with_dns_upstreams(self.dns_upstreams.clone())
    }
    pub fn id(&self) -> &NetworkId {
        &self.id
    }
    pub fn devices(&self) -> &[Device] {
        &self.devices
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    pub(crate) network: NetworkId,
    pub(crate) device: DeviceId,
}
impl Endpoint {
    pub fn new(network: NetworkId, device: DeviceId) -> Self {
        Self { network, device }
    }
    pub fn network(&self) -> &NetworkId {
        &self.network
    }
    pub fn device(&self) -> &DeviceId {
        &self.device
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rule {
    source: Endpoint,
    destination: Endpoint,
    action: Action,
}
impl Rule {
    pub fn new(source: Endpoint, destination: Endpoint, action: Action) -> Self {
        Self {
            source,
            destination,
            action,
        }
    }
    fn matches(&self, source: &Endpoint, destination: &Endpoint) -> bool {
        self.source == *source && self.destination == *destination
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Grant {
    source: Endpoint,
    destination: Endpoint,
}
impl Grant {
    pub fn new(source: Endpoint, destination: Endpoint) -> Self {
        Self {
            source,
            destination,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Policy {
    global_rules: Vec<Rule>,
    local_rules: Vec<Rule>,
    grants: Vec<Grant>,
}
impl Policy {
    pub fn new(global_rules: Vec<Rule>, local_rules: Vec<Rule>, grants: Vec<Grant>) -> Self {
        Self {
            global_rules,
            local_rules,
            grants,
        }
    }

    /// Remove references to deleted registrations using the complete endpoint,
    /// since device IDs are scoped to their owner and may repeat across networks.
    pub(crate) fn retaining_endpoints(&self, networks: &[Network]) -> Self {
        let endpoints: BTreeSet<_> = networks
            .iter()
            .flat_map(|network| {
                network
                    .devices()
                    .iter()
                    .map(move |device| (network.id(), device.id()))
            })
            .collect();
        let exists =
            |endpoint: &Endpoint| endpoints.contains(&(endpoint.network(), endpoint.device()));
        let retain_rules = |rules: &[Rule]| {
            rules
                .iter()
                .filter(|rule| exists(&rule.source) && exists(&rule.destination))
                .cloned()
                .collect()
        };
        Self::new(
            retain_rules(&self.global_rules),
            retain_rules(&self.local_rules),
            self.grants
                .iter()
                .filter(|grant| exists(&grant.source) && exists(&grant.destination))
                .cloned()
                .collect(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub(crate) generation: u64,
    pub(crate) networks: Vec<Network>,
    pub(crate) policy: Policy,
}
impl Config {
    pub fn new(
        generation: u64,
        networks: Vec<Network>,
        policy: Policy,
    ) -> Result<Self, DomainError> {
        if generation == 0 {
            return Err(DomainError::InvalidGeneration);
        }
        if networks.len() > MAX_NETWORKS
            || networks.iter().map(|n| n.devices.len()).sum::<usize>() > MAX_DEVICES
            || policy
                .global_rules
                .len()
                .saturating_add(policy.local_rules.len())
                .saturating_add(policy.grants.len())
                > MAX_POLICY_RULES
        {
            return Err(DomainError::LimitExceeded);
        }
        let mut ids = BTreeSet::new();
        for network in &networks {
            if !ids.insert(&network.id) {
                return Err(DomainError::DuplicateNetworkId);
            }
        }
        let config = Self {
            generation,
            networks,
            policy,
        };
        config.validate_policy()?;
        Ok(config)
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn with_networks(&self, networks: Vec<Network>) -> Result<Self, DomainError> {
        Self::new(self.generation, networks, self.policy.clone())
    }
    pub fn networks(&self) -> &[Network] {
        &self.networks
    }
    /// Resolve an address in its authenticated source context. The result is a
    /// routing identity, not authorization: callers must still apply policy.
    /// Remote candidates come only from exact directional grants, and denies
    /// never make an otherwise ambiguous destination unambiguous.
    pub fn resolve_destination(
        &self,
        source: &Endpoint,
        destination: IpAddr,
    ) -> Result<Endpoint, crate::RouteError> {
        let source_network = self
            .endpoint_network(source)
            .ok_or(crate::RouteError::UnknownSource)?;
        if let Some(device) = source_network
            .devices
            .iter()
            .find(|device| device.addresses.contains(&destination))
        {
            return Ok(Endpoint::new(source.network.clone(), device.id.clone()));
        }
        let mut candidate = None;
        for grant in self
            .policy
            .grants
            .iter()
            .filter(|grant| grant.source == *source)
        {
            let target = self
                .networks
                .iter()
                .find(|network| network.id == grant.destination.network)
                .and_then(|network| {
                    network
                        .devices
                        .iter()
                        .find(|device| device.id == grant.destination.device)
                })
                .ok_or(crate::RouteError::UnknownDestination)?;
            if !target.addresses.contains(&destination) {
                continue;
            }
            if candidate.is_some_and(|existing| existing != &grant.destination) {
                return Err(crate::RouteError::AmbiguousDestination);
            }
            candidate = Some(&grant.destination);
        }
        candidate
            .cloned()
            .ok_or(crate::RouteError::UnknownDestination)
    }
    pub fn validate_successor(&self, candidate: &Self) -> Result<(), DomainError> {
        if candidate.generation <= self.generation {
            return Err(DomainError::GenerationNotIncreasing);
        }
        Ok(())
    }
    /// Builds the direct grant closure of the original assigned scope. Remote
    /// metadata never expands the gateway's scope or adds transitive grants.
    pub(crate) fn project_networks(&self, assigned: &[NetworkId]) -> Result<Self, DomainError> {
        let scope: BTreeSet<_> = assigned.iter().collect();
        let mut retained = scope.clone();
        let grants: Vec<_> = self
            .policy
            .grants
            .iter()
            .filter(|grant| {
                scope.contains(&grant.source.network) || scope.contains(&grant.destination.network)
            })
            .cloned()
            .collect();
        for grant in &grants {
            retained.insert(&grant.source.network);
            retained.insert(&grant.destination.network);
        }
        let retain_rule = |rule: &&Rule| {
            retained.contains(&rule.source.network) && retained.contains(&rule.destination.network)
        };
        let global_rules = self
            .policy
            .global_rules
            .iter()
            .filter(retain_rule)
            .cloned()
            .collect();
        let local_rules = self
            .policy
            .local_rules
            .iter()
            .filter(retain_rule)
            .cloned()
            .collect();
        let networks = self
            .networks
            .iter()
            .filter(|network| retained.contains(&network.id))
            .cloned()
            .collect();
        Self::new(
            self.generation,
            networks,
            Policy::new(global_rules, local_rules, grants),
        )
    }
    fn endpoint_network(&self, endpoint: &Endpoint) -> Option<&Network> {
        self.networks
            .iter()
            .find(|n| n.id == endpoint.network && n.devices.iter().any(|d| d.id == endpoint.device))
    }
    fn validate_policy(&self) -> Result<(), DomainError> {
        for rule in self
            .policy
            .global_rules
            .iter()
            .chain(&self.policy.local_rules)
        {
            if self.endpoint_network(&rule.source).is_none()
                || self.endpoint_network(&rule.destination).is_none()
            {
                return Err(DomainError::InvalidPolicyReference);
            }
        }
        if self
            .policy
            .local_rules
            .iter()
            .any(|r| r.source.network != r.destination.network)
        {
            return Err(DomainError::CrossNetworkLocalRule);
        }
        for grant in &self.policy.grants {
            let source = self
                .endpoint_network(&grant.source)
                .ok_or(DomainError::InvalidPolicyReference)?;
            let destination = self
                .endpoint_network(&grant.destination)
                .ok_or(DomainError::InvalidPolicyReference)?;
            if source.id == destination.id {
                return Err(DomainError::InvalidGrant);
            }
            let addresses: BTreeSet<_> = source.devices.iter().flat_map(|d| &d.addresses).collect();
            if destination
                .devices
                .iter()
                .flat_map(|d| &d.addresses)
                .any(|a| addresses.contains(a))
            {
                return Err(DomainError::AmbiguousGrant);
            }
        }
        Ok(())
    }
    /// Configuration-level authorization only. Packet authentication and filtering
    /// must establish these identities and enforce IP/protocol/port rules later.
    pub fn decision(&self, source: &Endpoint, destination: &Endpoint) -> Action {
        if self.endpoint_network(source).is_none_or(Network::suspended)
            || self
                .endpoint_network(destination)
                .is_none_or(Network::suspended)
            || self
                .policy
                .global_rules
                .iter()
                .any(|r| r.action == Action::Deny && r.matches(source, destination))
        {
            return Action::Deny;
        }
        if source.network == destination.network {
            if self
                .policy
                .local_rules
                .iter()
                .any(|r| r.action == Action::Deny && r.matches(source, destination))
            {
                return Action::Deny;
            }
            if self
                .endpoint_network(source)
                .is_some_and(Network::private_lan)
                || self
                    .policy
                    .local_rules
                    .iter()
                    .any(|r| r.action == Action::Allow && r.matches(source, destination))
            {
                return Action::Allow;
            }
        } else if self
            .policy
            .grants
            .iter()
            .any(|g| g.source == *source && g.destination == *destination)
        {
            return Action::Allow;
        }
        Action::Deny
    }
}
