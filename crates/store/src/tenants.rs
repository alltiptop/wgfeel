use crate::{DiskSecret, StoreError};
use serde::{Deserialize, Serialize, ser::SerializeSeq};
use std::fmt;
use wgfeel_core::{Config, GatewayProjection, MAX_NETWORKS, NetworkId, NodeKeys, TenantPrivateKey};

/// Keys provisioned on this node. Absence means no local context, not a request
/// to generate a key. This type deliberately has no general serde or Clone API.
#[derive(Debug, Default)]
pub struct LocalTenants(Vec<(NetworkId, TenantPrivateKey)>);

impl LocalTenants {
    pub fn new(entries: Vec<(NetworkId, TenantPrivateKey)>) -> Result<Self, StoreError> {
        if entries.len() > MAX_NETWORKS {
            return Err(StoreError::InvalidLocalTenants);
        }
        for (index, (network, key)) in entries.iter().enumerate() {
            if entries[..index]
                .iter()
                .any(|(previous_network, previous_key)| {
                    network == previous_network || key.expose_bytes() == previous_key.expose_bytes()
                })
            {
                return Err(StoreError::InvalidLocalTenants);
            }
        }
        // Preserve the allocation: do not sort or copy secrets into a growing map.
        Ok(Self(entries))
    }
    pub fn network_ids(&self) -> impl Iterator<Item = &NetworkId> {
        self.0.iter().map(|(id, _)| id)
    }
    pub fn private_key(&self, id: &NetworkId) -> Option<&TenantPrivateKey> {
        self.0
            .iter()
            .find(|(network, _)| network == id)
            .map(|(_, key)| key)
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn validate_projection(
        &self,
        projection: &GatewayProjection,
        node_key: &NodeKeys,
    ) -> Result<(), StoreError> {
        self.validate_context(projection.config(), node_key)?;
        let assigned = projection.assignment().tenants();
        if self.len() != assigned.len()
            || assigned
                .iter()
                .any(|assignment| self.private_key(assignment.network()).is_none())
        {
            return Err(StoreError::InvalidLocalTenants);
        }
        // Derived-key correspondence is checked by the runtime crypto builder.
        Ok(())
    }

    pub(crate) fn validate_context(
        &self,
        config: &Config,
        node_key: &NodeKeys,
    ) -> Result<(), StoreError> {
        for (network, key) in &self.0 {
            if !config.networks().iter().any(|entry| entry.id() == network)
                || (key.expose_bytes() == node_key.service().expose_bytes()
                    || key.expose_bytes() == node_key.gateway().expose_bytes())
            {
                return Err(StoreError::InvalidLocalTenants);
            }
        }
        // Byte inequality does not establish different derived public keys.
        // The WireGuard runtime checks the derived public keys when building contexts.
        Ok(())
    }
}

pub(crate) struct ReadTenants(pub(crate) LocalTenants);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadTenant {
    network: String,
    private_key: DiskSecret,
}

impl<'de> Deserialize<'de> for ReadTenants {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TenantVisitor;
        impl<'de> serde::de::Visitor<'de> for TenantVisitor {
            type Value = ReadTenants;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded array of local tenant keys")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                // Allocate before the first secret is parsed. No push can reallocate
                // and leave a freed copy of earlier inline private key material.
                let mut entries = Vec::with_capacity(MAX_NETWORKS);
                while let Some(entry) = sequence.next_element::<ReadTenant>()? {
                    if entries.len() == MAX_NETWORKS {
                        return Err(serde::de::Error::custom("too many local contexts"));
                    }
                    let network = NetworkId::new(&entry.network)
                        .map_err(|_| serde::de::Error::custom("invalid local context"))?;
                    let key = TenantPrivateKey::new(*entry.private_key.0)
                        .map_err(|_| serde::de::Error::custom("invalid local context"))?;
                    entries.push((network, key));
                }
                let local = LocalTenants::new(entries)
                    .map_err(|_| serde::de::Error::custom("invalid local contexts"))?;
                Ok(ReadTenants(local))
            }
        }
        deserializer.deserialize_seq(TenantVisitor)
    }
}

// Explicit secret access is confined to this private protected-file adapter.
pub(crate) struct WriteTenants<'a>(pub &'a LocalTenants);

#[derive(Serialize)]
struct WriteTenant<'a> {
    network: &'a str,
    private_key: &'a [u8; 32],
}

impl Serialize for WriteTenants<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (network, key) in &self.0.0 {
            sequence.serialize_element(&WriteTenant {
                network: network.as_str(),
                private_key: key.expose_bytes(),
            })?;
        }
        sequence.end()
    }
}
