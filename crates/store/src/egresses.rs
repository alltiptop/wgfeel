//! Private provider keys in the authoritative snapshot.
use crate::{DiskSecret, StoreError};
use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use serde::{Deserialize, Serialize, ser::SerializeSeq};
use wgfeel_core::{
    DevicePublicKey, DomainError, EgressId, EgressPrivateKey, EgressProfile, MAX_EGRESSES,
    PresharedKey,
};

#[derive(Debug)]
pub struct EgressKeys {
    private: EgressPrivateKey,
    preshared: Option<PresharedKey>,
}
impl EgressKeys {
    pub fn new(private: EgressPrivateKey, preshared: Option<PresharedKey>) -> Self {
        Self { private, preshared }
    }
    pub fn private_key(&self) -> &EgressPrivateKey {
        &self.private
    }
    pub fn preshared_key(&self) -> Option<&PresharedKey> {
        self.preshared.as_ref()
    }
    pub fn same_material(&self, other: &Self) -> bool {
        self.private.expose_bytes() == other.private.expose_bytes()
            && self.preshared_key().map(PresharedKey::expose_bytes)
                == other.preshared_key().map(PresharedKey::expose_bytes)
    }
    pub fn interface_public_key(
        &self,
        peer: &DevicePublicKey,
    ) -> Result<DevicePublicKey, DomainError> {
        let key = PrivateKey::from_private_key(&X25519, self.private.expose_bytes())
            .map_err(|_| DomainError::InvalidKey)?;
        agreement::agree(
            &key,
            UnparsedPublicKey::new(&X25519, peer.as_bytes()),
            DomainError::InvalidKey,
            |_| Ok(()),
        )?;
        let public = key
            .compute_public_key()
            .map_err(|_| DomainError::InvalidKey)?;
        DevicePublicKey::new(
            public
                .as_ref()
                .try_into()
                .map_err(|_| DomainError::InvalidKey)?,
        )
    }
    fn copy_owned(&self) -> Result<Self, DomainError> {
        Ok(Self::new(
            EgressPrivateKey::new(*self.private.expose_bytes())?,
            self.preshared
                .as_ref()
                .map(|p| PresharedKey::new(*p.expose_bytes()))
                .transpose()?,
        ))
    }
}

#[derive(Debug)]
pub(crate) struct EgressSecrets(Vec<(EgressId, Box<EgressKeys>)>);
impl Default for EgressSecrets {
    fn default() -> Self {
        Self(Vec::with_capacity(MAX_EGRESSES))
    }
}
impl EgressSecrets {
    pub fn get(&self, id: &EgressId) -> Option<&EgressKeys> {
        self.0
            .iter()
            .find(|(i, _)| i == id)
            .map(|(_, k)| k.as_ref())
    }
    pub fn replace(&mut self, id: &EgressId, keys: EgressKeys) -> Result<bool, DomainError> {
        let (_, old) = self
            .0
            .iter_mut()
            .find(|(i, _)| i == id)
            .ok_or(DomainError::InvalidEgress)?;
        let changed = !old.same_material(&keys);
        **old = keys;
        Ok(changed)
    }
    pub fn select(&self, profiles: &[EgressProfile]) -> Result<LocalEgressSecrets, StoreError> {
        let mut selected = Self::default();
        for p in profiles {
            let keys = self.get(&p.id).ok_or(StoreError::InvalidState)?;
            selected
                .insert(
                    p.id.clone(),
                    keys.copy_owned().map_err(StoreError::InvalidConfig)?,
                )
                .map_err(StoreError::InvalidConfig)?;
        }
        Ok(LocalEgressSecrets(selected))
    }
    pub fn insert(&mut self, id: EgressId, keys: EgressKeys) -> Result<(), DomainError> {
        if self.0.len() >= MAX_EGRESSES {
            return Err(DomainError::LimitExceeded);
        }
        if self.0.iter().any(|(old, _)| *old == id) {
            return Err(DomainError::InvalidEgress);
        }
        self.0.push((id, Box::new(keys)));
        Ok(())
    }
    pub fn copy_owned(&self) -> Result<Self, DomainError> {
        let mut result = Self::default();
        for (id, keys) in &self.0 {
            result.insert(id.clone(), keys.copy_owned()?)?;
        }
        Ok(result)
    }
    pub fn retain(&mut self, profiles: &[EgressProfile]) {
        self.0
            .retain(|(id, _)| profiles.iter().any(|p| p.id == *id));
    }
    pub fn validate(&self, profiles: &[EgressProfile]) -> Result<(), StoreError> {
        if self.0.len() != profiles.len() {
            return Err(StoreError::InvalidState);
        }
        for profile in profiles {
            let (_, keys) = self
                .0
                .iter()
                .find(|(id, _)| id == &profile.id)
                .ok_or(StoreError::InvalidState)?;
            if keys
                .interface_public_key(&profile.peer_public_key)
                .map_err(StoreError::InvalidConfig)?
                != profile.interface_public_key
                || keys.preshared.is_some() != profile.has_preshared_key
            {
                return Err(StoreError::InvalidState);
            }
        }
        Ok(())
    }
}
pub(crate) struct WriteEgressSecrets<'a>(pub &'a EgressSecrets);
impl Serialize for WriteEgressSecrets<'_> {
    fn serialize<S: serde::Serializer>(&self, se: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Entry<'a> {
            id: &'a EgressId,
            private_key: &'a [u8; 32],
            preshared_key: Option<&'a [u8; 32]>,
        }
        let mut seq = se.serialize_seq(Some(self.0.0.len()))?;
        for (id, keys) in &self.0.0 {
            seq.serialize_element(&Entry {
                id,
                private_key: keys.private.expose_bytes(),
                preshared_key: keys.preshared.as_ref().map(PresharedKey::expose_bytes),
            })?;
        }
        seq.end()
    }
}
impl<'de> Deserialize<'de> for EgressSecrets {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Entry {
            id: EgressId,
            private_key: DiskSecret,
            preshared_key: Option<DiskSecret>,
        }
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = EgressSecrets;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bounded provider keys")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut result = EgressSecrets::default();
                while let Some(entry) = seq.next_element::<Entry>()? {
                    let private = EgressPrivateKey::new(*entry.private_key.0)
                        .map_err(serde::de::Error::custom)?;
                    let preshared = entry
                        .preshared_key
                        .map(|p| PresharedKey::new(*p.0))
                        .transpose()
                        .map_err(serde::de::Error::custom)?;
                    result
                        .insert(entry.id, EgressKeys::new(private, preshared))
                        .map_err(serde::de::Error::custom)?;
                }
                Ok(result)
            }
        }
        de.deserialize_seq(Visitor)
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(transparent)]
pub struct LocalEgressSecrets(pub(crate) EgressSecrets);
impl LocalEgressSecrets {
    pub fn get(&self, id: &EgressId) -> Option<&EgressKeys> {
        self.0.get(id)
    }
    pub fn same_material(&self, other: &Self) -> bool {
        self.0.0.len() == other.0.0.len()
            && self
                .0
                .0
                .iter()
                .all(|(id, k)| other.get(id).is_some_and(|old| old.same_material(k)))
    }
    pub fn validate(&self, projection: &wgfeel_core::GatewayProjection) -> Result<(), StoreError> {
        self.0.validate(projection.owned_egresses())
    }
}
pub(crate) fn present<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<Option<LocalEgressSecrets>, D::Error> {
    LocalEgressSecrets::deserialize(de).map(Some)
}
