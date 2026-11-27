//! Explicit private material boundary. Public configuration never serializes it.
use crate::{
    DiskSecret, EgressKeys, StoreError,
    egresses::{EgressSecrets, WriteEgressSecrets},
};
use serde::{Deserialize, Serialize};
use wgfeel_core::{
    ClientId, DeviceId, DevicePrivateKey, MAX_DEVICES, MAX_GATEWAYS, MAX_NETWORKS,
    ManagementDocument, NetworkId, NodeId, TenantPrivateKey,
};
const MAX_TENANTS: usize = MAX_GATEWAYS * MAX_NETWORKS;
#[derive(Debug)]
pub struct ManagementSecrets {
    devices: Vec<(ClientId, DeviceId, DevicePrivateKey)>,
    egresses: EgressSecrets,
    tenants: Vec<(NodeId, NetworkId, TenantPrivateKey)>,
}
impl Default for ManagementSecrets {
    fn default() -> Self {
        Self {
            devices: Vec::with_capacity(MAX_DEVICES),
            egresses: EgressSecrets::default(),
            tenants: Vec::with_capacity(MAX_TENANTS),
        }
    }
}
impl ManagementSecrets {
    pub fn device(&self, client: &ClientId, device: &DeviceId) -> Option<&DevicePrivateKey> {
        self.devices
            .iter()
            .find(|(c, d, _)| c == client && d == device)
            .map(|(_, _, key)| key)
    }
    pub fn tenant(&self, node: &NodeId, network: &NetworkId) -> Option<&TenantPrivateKey> {
        self.tenants
            .iter()
            .find(|(n, t, _)| n == node && t == network)
            .map(|(_, _, key)| key)
    }
    pub fn insert_device(
        &mut self,
        client: ClientId,
        device: DeviceId,
        key: DevicePrivateKey,
    ) -> Result<(), StoreError> {
        if self.devices.len() == MAX_DEVICES || self.device(&client, &device).is_some() {
            return Err(StoreError::InvalidState);
        }
        self.devices.push((client, device, key));
        Ok(())
    }
    pub fn insert_tenant(
        &mut self,
        node: NodeId,
        network: NetworkId,
        key: TenantPrivateKey,
    ) -> Result<(), StoreError> {
        if self.tenants.len() == MAX_TENANTS || self.tenant(&node, &network).is_some() {
            return Err(StoreError::InvalidState);
        }
        self.tenants.push((node, network, key));
        Ok(())
    }
    pub(crate) fn select_egress_keys(
        &self,
        projection: &wgfeel_core::GatewayProjection,
    ) -> Result<crate::LocalEgressSecrets, StoreError> {
        self.egresses.select(projection.owned_egresses())
    }
    pub fn replace_egress(
        &mut self,
        id: &wgfeel_core::EgressId,
        keys: EgressKeys,
    ) -> Result<bool, wgfeel_core::DomainError> {
        self.egresses.replace(id, keys)
    }
    pub fn insert_egress(
        &mut self,
        id: wgfeel_core::EgressId,
        keys: EgressKeys,
    ) -> Result<(), wgfeel_core::DomainError> {
        self.egresses.insert(id, keys)
    }
    pub fn copy_owned(&self) -> Result<Self, StoreError> {
        let mut result = Self {
            egresses: self
                .egresses
                .copy_owned()
                .map_err(StoreError::InvalidConfig)?,
            ..Self::default()
        };
        for (client, device, key) in &self.devices {
            result.insert_device(
                client.clone(),
                device.clone(),
                DevicePrivateKey::new(*key.expose_bytes()).map_err(StoreError::InvalidConfig)?,
            )?;
        }
        for (node, network, key) in &self.tenants {
            result.insert_tenant(
                node.clone(),
                network.clone(),
                TenantPrivateKey::new(*key.expose_bytes()).map_err(StoreError::InvalidConfig)?,
            )?;
        }
        Ok(result)
    }
    pub fn retain_document(&mut self, document: &ManagementDocument) {
        self.egresses.retain(document.routing().egresses());
        self.devices.retain(|(client, device, _)| {
            document.clients().iter().any(|owner| {
                owner.id() == client && owner.devices().iter().any(|entry| entry.id() == device)
            })
        });
        self.tenants.retain(|(node, network, _)| {
            document.routing().assignments().iter().any(|entry| {
                entry.recipient() == node
                    && entry
                        .tenants()
                        .iter()
                        .any(|tenant| tenant.network() == network)
            })
        });
    }
    pub(crate) fn validate(&self, document: &ManagementDocument) -> Result<(), StoreError> {
        self.egresses.validate(document.routing().egresses())?;
        if self.devices.iter().any(|(client, device, _)| {
            !document.clients().iter().any(|owner| {
                owner.id() == client && owner.devices().iter().any(|entry| entry.id() == device)
            })
        }) || self.tenants.iter().any(|(node, network, _)| {
            !document.routing().assignments().iter().any(|entry| {
                entry.recipient() == node
                    && entry
                        .tenants()
                        .iter()
                        .any(|tenant| tenant.network() == network)
            })
        }) {
            return Err(StoreError::InvalidState);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceEntry {
    client: String,
    device: String,
    private_key: DiskSecret,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantEntry {
    node: String,
    network: String,
    private_key: DiskSecret,
}
// Preallocate before the first secret: parsing cannot leave copies in freed,
// reallocated Vec storage. Deserialize each entry straight into its final owner.
struct Devices(ManagementSecrets);
impl<'de> Deserialize<'de> for Devices {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Devices;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bounded private device keys")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut result = ManagementSecrets::default();
                while let Some(entry) = seq.next_element::<DeviceEntry>()? {
                    let client = ClientId::new(&entry.client).map_err(serde::de::Error::custom)?;
                    let device = DeviceId::new(&entry.device).map_err(serde::de::Error::custom)?;
                    let key = DevicePrivateKey::new(*entry.private_key.0)
                        .map_err(serde::de::Error::custom)?;
                    result
                        .insert_device(client, device, key)
                        .map_err(serde::de::Error::custom)?;
                }
                Ok(Devices(result))
            }
        }
        de.deserialize_seq(Visitor)
    }
}
struct Tenants(ManagementSecrets);
impl<'de> Deserialize<'de> for Tenants {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Tenants;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bounded private gateway keys")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut result = ManagementSecrets::default();
                while let Some(entry) = seq.next_element::<TenantEntry>()? {
                    let node = NodeId::new(&entry.node).map_err(serde::de::Error::custom)?;
                    let network =
                        NetworkId::new(&entry.network).map_err(serde::de::Error::custom)?;
                    let key = TenantPrivateKey::new(*entry.private_key.0)
                        .map_err(serde::de::Error::custom)?;
                    result
                        .insert_tenant(node, network, key)
                        .map_err(serde::de::Error::custom)?;
                }
                Ok(Tenants(result))
            }
        }
        de.deserialize_seq(Visitor)
    }
}
impl<'de> Deserialize<'de> for ManagementSecrets {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            devices: Devices,
            tenants: Tenants,
            #[serde(default)]
            egresses: EgressSecrets,
        }
        let raw = Raw::deserialize(de)?;
        Ok(Self {
            devices: raw.devices.0.devices,
            tenants: raw.tenants.0.tenants,
            egresses: raw.egresses,
        })
    }
}
pub(crate) struct WriteSecrets<'a>(pub &'a ManagementSecrets);
impl Serialize for WriteSecrets<'_> {
    fn serialize<S: serde::Serializer>(&self, se: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Device<'a> {
            client: &'a ClientId,
            device: &'a DeviceId,
            private_key: &'a [u8; 32],
        }
        #[derive(Serialize)]
        struct Tenant<'a> {
            node: &'a NodeId,
            network: &'a NetworkId,
            private_key: &'a [u8; 32],
        }
        #[derive(Serialize)]
        struct Wire<'a> {
            devices: Vec<Device<'a>>,
            tenants: Vec<Tenant<'a>>,
            egresses: WriteEgressSecrets<'a>,
        }
        Wire {
            egresses: WriteEgressSecrets(&self.0.egresses),
            devices: self
                .0
                .devices
                .iter()
                .map(|(client, device, key)| Device {
                    client,
                    device,
                    private_key: key.expose_bytes(),
                })
                .collect(),
            tenants: self
                .0
                .tenants
                .iter()
                .map(|(node, network, key)| Tenant {
                    node,
                    network,
                    private_key: key.expose_bytes(),
                })
                .collect(),
        }
        .serialize(se)
    }
}
