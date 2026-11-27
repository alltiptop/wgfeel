//! Authoritative placement, key reservations, and per-user route selection.
use crate::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

pub const MAX_EGRESSES_PER_NODE: usize = 16;
pub const MAX_EGRESSES_PER_USER: usize = 8;
pub const MAX_ROUTES_PER_ASSIGNMENT: usize = 32;
pub const MAX_DNS_ZONES_PER_ASSIGNMENT: usize = 8;
pub const MAX_EGRESS_KEY_RESERVATIONS: usize = 150;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct DnsZone(#[serde(deserialize_with = "read_zone")] String);
fn read_zone<'de, D: serde::Deserializer<'de>>(de: D) -> Result<String, D::Error> {
    let zone = String::deserialize(de)?.to_ascii_lowercase();
    if zone.is_empty()
        || zone.len() > 253
        || zone == "feel.internal"
        || zone.ends_with(".feel.internal")
        || zone.split('.').any(|l| {
            l.is_empty()
                || l.len() > 63
                || l.starts_with('-')
                || l.ends_with('-')
                || !l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(serde::de::Error::custom("invalid DNS zone"));
    }
    Ok(zone)
}
impl DnsZone {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum EgressDnsSelection {
    None {},
    Default {},
    Zones { zones: Vec<DnsZone> },
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UserEgressAssignment {
    pub egress_id: EgressId,
    pub routes: Vec<IpPrefix>,
    pub dns: EgressDnsSelection,
}
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UserEgresses {
    pub user: ClientId,
    pub network: NetworkId,
    pub egresses: Vec<UserEgressAssignment>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressKeyReservation {
    #[serde(with = "crate::egress::public_key")]
    #[schemars(with = "String")]
    pub interface_public_key: DevicePublicKey,
    pub former_node: NodeId,
    #[serde(with = "crate::egress::public_key")]
    #[schemars(with = "String")]
    pub former_service_public_key: DevicePublicKey,
    pub removal_generation: u64,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct EgressPolicy {
    pub profiles: Vec<EgressProfile>,
    pub users: Vec<UserEgresses>,
    pub reservations: Vec<EgressKeyReservation>,
}
impl EgressPolicy {
    pub fn profile(&self, id: &EgressId) -> Option<&EgressProfile> {
        self.profiles.iter().find(|p| p.id == *id)
    }
    pub fn reservation(&self, key: &DevicePublicKey) -> Option<&EgressKeyReservation> {
        self.reservations
            .iter()
            .find(|r| r.interface_public_key == *key)
    }
    pub fn grants(&self, id: &ClientId) -> &[UserEgressAssignment] {
        self.users
            .iter()
            .find(|u| u.user == *id)
            .map_or(&[], |u| u.egresses.as_slice())
    }
    pub(crate) fn validate(&self, routing: &ManagementConfig) -> Result<(), DomainError> {
        if self.profiles.len() > MAX_EGRESSES
            || self.users.len() > MAX_CLIENTS
            || self.reservations.len() + self.profiles.iter().filter(|p| p.node.is_some()).count()
                > MAX_EGRESS_KEY_RESERVATIONS
        {
            return Err(DomainError::LimitExceeded);
        }
        let mut per_node = BTreeMap::new();
        let mut reserved = BTreeSet::new();
        for r in &self.reservations {
            if !canonical_public_key(r.interface_public_key.as_bytes())
                || r.removal_generation == 0
                || r.removal_generation > routing.generation()
                || !reserved.insert(&r.interface_public_key)
            {
                return Err(DomainError::InvalidEgress);
            }
            if routing
                .assignments()
                .iter()
                .find(|n| n.recipient() == &r.former_node)
                .is_some_and(|n| n.service_public_key() != &r.former_service_public_key)
            {
                return Err(DomainError::EgressKeyPendingWithdrawal);
            }
        }
        for p in &self.profiles {
            if let Some(id) = p.node.as_ref().or(p.pending_node.as_ref()) {
                if !routing.assignments().iter().any(|n| {
                    n.recipient() == id && n.traffic().accepts_devices() && n.endpoint().is_some()
                }) {
                    return Err(DomainError::InvalidEgress);
                }
                let count = per_node.entry(id).or_insert(0);
                *count += 1;
                if *count > MAX_EGRESSES_PER_NODE {
                    return Err(DomainError::LimitExceeded);
                }
            }
            let reservation = self.reservation(&p.interface_public_key);
            if (p.node.is_some() && reservation.is_some())
                || p.pending_node
                    .as_ref()
                    .is_some_and(|id| reservation.is_none_or(|r| &r.former_node == id))
            {
                return Err(DomainError::EgressKeyPendingWithdrawal);
            }
        }
        let mut users = BTreeSet::new();
        let mut networks = BTreeSet::new();
        for user in &self.users {
            if !users.insert(&user.user) || !networks.insert(&user.network) {
                return Err(DomainError::InvalidClientOwnership);
            }
            let network = routing
                .config()
                .networks()
                .iter()
                .find(|n| n.id() == &user.network)
                .ok_or(DomainError::InvalidClientOwnership)?;
            self.validate_grants(user, network, routing)?;
        }
        Ok(())
    }
    fn validate_grants(
        &self,
        user: &UserEgresses,
        network: &Network,
        routing: &ManagementConfig,
    ) -> Result<(), DomainError> {
        if user.egresses.is_empty() || user.egresses.len() > MAX_EGRESSES_PER_USER {
            return Err(DomainError::InvalidEgress);
        }
        let mut ids = BTreeSet::new();
        let mut routes = BTreeSet::new();
        let mut zones = BTreeSet::new();
        let mut default = false;
        for grant in &user.egresses {
            let p = self
                .profile(&grant.egress_id)
                .ok_or(DomainError::InvalidEgress)?;
            if !ids.insert(&p.id)
                || grant.routes.is_empty()
                || grant.routes.len() > MAX_ROUTES_PER_ASSIGNMENT
            {
                return Err(DomainError::InvalidEgress);
            }
            if let Some(id) = p.node.as_ref().or(p.pending_node.as_ref()) {
                let node = routing
                    .assignments()
                    .iter()
                    .find(|n| n.recipient() == id)
                    .ok_or(DomainError::InvalidEgress)?;
                if !node.networks().contains(network.id())
                    || !node.tenants().iter().any(|t| t.network() == network.id())
                {
                    return Err(DomainError::NodeOutOfScope);
                }
            }
            for &prefix in &grant.routes {
                if prefix.internal()
                    || !p
                        .addresses
                        .iter()
                        .any(|a| a.is_ipv4() == prefix.network().is_ipv4())
                    || !p.allowed_ips.iter().any(|a| a.covers(prefix))
                {
                    return Err(DomainError::InvalidEgress);
                }
                if !routes.insert(prefix) {
                    return Err(DomainError::DuplicateEgressPrefix);
                }
            }
            match &grant.dns {
                EgressDnsSelection::None {} => continue,
                EgressDnsSelection::Default {} if std::mem::replace(&mut default, true) => {
                    return Err(DomainError::ConflictingDnsSelection);
                }
                EgressDnsSelection::Zones { zones: items } => {
                    if items.is_empty() || items.len() > MAX_DNS_ZONES_PER_ASSIGNMENT {
                        return Err(DomainError::InvalidEgress);
                    }
                    for z in items {
                        if !zones.insert(z.as_str()) {
                            return Err(DomainError::ConflictingDnsSelection);
                        }
                    }
                }
                _ => {}
            }
            let eligible = self.dns_servers(user, grant, routing.config(), None);
            if eligible.is_empty()
                || network.devices().iter().any(|d| {
                    self.dns_servers(user, grant, routing.config(), Some(d))
                        .is_empty()
                })
            {
                return Err(DomainError::InvalidEgress);
            }
        }
        Ok(())
    }
    pub fn dns_servers(
        &self,
        user: &UserEgresses,
        grant: &UserEgressAssignment,
        config: &Config,
        device: Option<&Device>,
    ) -> Vec<IpAddr> {
        let Some(p) = self.profile(&grant.egress_id) else {
            return vec![];
        };
        p.dns_servers
            .iter()
            .copied()
            .filter(|ip| {
                if IpPrefix::host(*ip).internal()
                    || device.is_some_and(|d| {
                        !d.addresses().iter().any(|a| a.is_ipv4() == ip.is_ipv4())
                            || !matches!(
                                config.resolve_destination(
                                    &Endpoint::new(user.network.clone(), d.id().clone()),
                                    *ip
                                ),
                                Err(RouteError::UnknownDestination)
                            )
                    })
                {
                    return false;
                }
                user.egresses
                    .iter()
                    .flat_map(|g| g.routes.iter().map(move |r| (r, &g.egress_id)))
                    .filter(|(r, _)| r.contains(*ip))
                    .max_by_key(|(r, _)| r.length())
                    .is_some_and(|(_, id)| id == &grant.egress_id)
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    Drop,
    InternalDns,
    Broadcast,
    Device(Endpoint),
    Egress {
        egress: EgressId,
        node: NodeId,
        prefix: IpPrefix,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    id: EgressId,
    node: Option<NodeId>,
    ipv4: bool,
    ipv6: bool,
    allowed_ips: Vec<IpPrefix>,
}
impl From<&EgressProfile> for Descriptor {
    fn from(p: &EgressProfile) -> Self {
        Self {
            id: p.id.clone(),
            node: p.node.clone(),
            ipv4: p.addresses.iter().any(IpAddr::is_ipv4),
            ipv6: p.addresses.iter().any(IpAddr::is_ipv6),
            allowed_ips: p.allowed_ips.clone(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Route {
    egress: EgressId,
    prefix: IpPrefix,
}
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectionEgress {
    owned: Vec<EgressProfile>,
    descriptors: Vec<Descriptor>,
    #[serde(deserialize_with = "read_scoped_routes")]
    routes: BTreeMap<NetworkId, Vec<Route>>,
}

fn read_scoped_routes<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<BTreeMap<NetworkId, Vec<Route>>, D::Error> {
    struct ScopedRoutes;
    impl<'de> serde::de::Visitor<'de> for ScopedRoutes {
        type Value = BTreeMap<NetworkId, Vec<Route>>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("one route table per assigned network")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut routes = BTreeMap::new();
            while let Some(network) = map.next_key()? {
                if routes.len() >= MAX_NETWORKS || routes.contains_key(&network) {
                    return Err(serde::de::Error::custom("duplicate or excess route table"));
                }
                routes.insert(network, map.next_value()?);
            }
            Ok(routes)
        }
    }
    de.deserialize_map(ScopedRoutes)
}

impl ProjectionEgress {
    pub(crate) fn for_node(policy: &EgressPolicy, node: &GatewayAssignment) -> Self {
        let mut result = Self::default();
        let mut used = BTreeSet::new();
        for u in policy
            .users
            .iter()
            .filter(|u| node.networks().contains(&u.network))
        {
            let mut routes = Vec::new();
            for a in &u.egresses {
                used.insert(&a.egress_id);
                routes.extend(a.routes.iter().map(|&prefix| Route {
                    egress: a.egress_id.clone(),
                    prefix,
                }));
            }
            routes.sort_by_key(|r| (std::cmp::Reverse(r.prefix.length()), r.prefix));
            result.routes.insert(u.network.clone(), routes);
        }
        for p in &policy.profiles {
            if used.contains(&p.id) {
                result.descriptors.push(p.into())
            }
            if p.node.as_ref() == Some(node.recipient()) {
                result.owned.push(p.clone())
            }
        }
        result
    }
    pub(crate) fn validate(&self, p: &GatewayProjection) -> Result<(), DomainError> {
        if self.owned.is_empty() && self.descriptors.is_empty() && self.routes.is_empty() {
            return Ok(());
        }
        if self.owned.len() > MAX_EGRESSES_PER_NODE
            || self.descriptors.len() > MAX_EGRESSES
            || self.routes.len() > MAX_NETWORKS
            || p.is_revoked()
            || !p.assignment().traffic().carries_user_traffic()
        {
            return Err(DomainError::InvalidProjection);
        }
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for n in p.mesh().iter().chain(std::iter::once(p.assignment())) {
            keys.extend(
                n.transport_public_keys()
                    .map(DevicePublicKey::x25519_coordinate),
            );
            keys.extend(
                n.tenants()
                    .iter()
                    .map(|t| t.public_key().x25519_coordinate()),
            );
        }
        keys.extend(
            p.config()
                .networks()
                .iter()
                .flat_map(Network::devices)
                .map(|d| d.public_key().x25519_coordinate()),
        );
        for owned in &self.owned {
            if !ids.insert(&owned.id)
                || !keys.insert(owned.interface_public_key.x25519_coordinate())
                || owned.node.as_ref() != Some(p.recipient())
                || !p.assignment().traffic().accepts_devices()
                || p.assignment().endpoint().is_none()
            {
                return Err(DomainError::InvalidProjection);
            }
        }
        if self
            .owned
            .iter()
            .any(|o| keys.contains(o.peer_public_key.as_bytes()))
        {
            return Err(DomainError::InvalidProjection);
        }
        let mut descriptors = BTreeMap::new();
        for d in &self.descriptors {
            if descriptors.insert(&d.id, d).is_some()
                || d.allowed_ips.is_empty()
                || d.allowed_ips.len() > MAX_ALLOWED_IPS_PER_EGRESS
                || !(d.ipv4 || d.ipv6)
                || self
                    .owned
                    .iter()
                    .find(|o| o.id == d.id)
                    .is_some_and(|o| Descriptor::from(o) != *d)
            {
                return Err(DomainError::InvalidProjection);
            }
            if let Some(node) = &d.node
                && ((node == p.recipient()
                    && !self.owned.iter().any(|o| Descriptor::from(o) == *d))
                    || (!p.mesh().is_empty()
                        && !p.mesh().iter().any(|n| {
                            n.recipient() == node
                                && n.traffic().accepts_devices()
                                && n.endpoint().is_some()
                        })))
            {
                return Err(DomainError::InvalidProjection);
            }
        }
        let mut used = BTreeSet::new();
        for (network, routes) in &self.routes {
            if !p.assignment().networks().contains(network)
                || routes.is_empty()
                || routes.len() > MAX_EGRESSES_PER_USER * MAX_ROUTES_PER_ASSIGNMENT
            {
                return Err(DomainError::InvalidProjection);
            }
            let mut seen = BTreeSet::new();
            let mut counts = BTreeMap::new();
            let mut previous = 128;
            for r in routes {
                let d = descriptors
                    .get(&r.egress)
                    .ok_or(DomainError::InvalidProjection)?;
                if !seen.insert(r.prefix)
                    || r.prefix.internal()
                    || r.prefix.length() > previous
                    || !(if r.prefix.network().is_ipv4() {
                        d.ipv4
                    } else {
                        d.ipv6
                    })
                    || !d.allowed_ips.iter().any(|a| a.covers(r.prefix))
                {
                    return Err(DomainError::InvalidProjection);
                }
                previous = r.prefix.length();
                used.insert(&d.id);
                *counts.entry(&d.id).or_insert(0) += 1;
                if let Some(node) = &d.node
                    && !p.mesh().is_empty()
                    && !p.mesh().iter().any(|n| {
                        n.recipient() == node && n.tenants().iter().any(|t| t.network() == network)
                    })
                {
                    return Err(DomainError::InvalidProjection);
                }
            }
            if counts.len() > MAX_EGRESSES_PER_USER
                || counts.values().any(|&n| n > MAX_ROUTES_PER_ASSIGNMENT)
            {
                return Err(DomainError::InvalidProjection);
            }
        }
        if used.len() != descriptors.len() {
            return Err(DomainError::InvalidProjection);
        }
        Ok(())
    }
}
impl GatewayProjection {
    pub fn owned_egresses(&self) -> &[EgressProfile] {
        &self.egress.owned
    }
    pub fn egress_route(
        &self,
        network: &NetworkId,
        egress: &EgressId,
        prefix: IpPrefix,
    ) -> Option<&NodeId> {
        let network = self
            .config()
            .networks()
            .iter()
            .find(|n| n.id() == network && !n.suspended())?;
        self.egress
            .routes
            .get(network.id())?
            .iter()
            .find(|r| r.egress == *egress && r.prefix == prefix)?;
        self.egress
            .descriptors
            .iter()
            .find(|d| d.id == *egress)?
            .node
            .as_ref()
    }
    pub fn classify_destination(&self, source: &Endpoint, dst: IpAddr) -> Destination {
        let Some(device) = self.device(source) else {
            return Destination::Drop;
        };
        if self.is_revoked()
            || !self.assignment().traffic().carries_user_traffic()
            || self
                .config()
                .networks()
                .iter()
                .any(|n| n.id() == source.network() && n.suspended())
        {
            return Destination::Drop;
        }
        if is_dns_address(dst) {
            return Destination::InternalDns;
        }
        if is_internal_broadcast_ipv4(dst) {
            return if self.broadcast_enabled(source) {
                Destination::Broadcast
            } else {
                Destination::Drop
            };
        }
        if dst.is_multicast() || dst == IpAddr::V4(std::net::Ipv4Addr::BROADCAST) {
            return Destination::Drop;
        }
        match self.config().resolve_destination(source, dst) {
            Ok(target) => {
                if self.decision(source, &target) != Action::Allow
                    || (target.network() != source.network()
                        && self
                            .device(&target)
                            .is_none_or(|d| d.gateway() != device.gateway()))
                {
                    return Destination::Drop;
                }
                return Destination::Device(target);
            }
            Err(RouteError::UnknownDestination) => {}
            Err(_) => return Destination::Drop,
        }
        if IpPrefix::host(dst).internal() {
            return Destination::Drop;
        }
        let Some(route) = self
            .egress
            .routes
            .get(source.network())
            .and_then(|routes| routes.iter().find(|r| r.prefix.contains(dst)))
        else {
            return Destination::Drop;
        };
        let Some(d) = self
            .egress
            .descriptors
            .iter()
            .find(|d| d.id == route.egress)
        else {
            return Destination::Drop;
        };
        match &d.node {
            Some(node) if d.allowed_ips.iter().any(|p| p.contains(dst)) => Destination::Egress {
                egress: d.id.clone(),
                node: node.clone(),
                prefix: route.prefix,
            },
            _ => Destination::Drop,
        }
    }
}
