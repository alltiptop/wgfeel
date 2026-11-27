use crate::{LocalTenants, StoreError, tenants};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use wgfeel_core::GatewayProjection;
pub use wgfeel_core::MAX_DELIVERY_BYTES;
use zeroize::Zeroizing;
#[derive(Debug)]
pub struct GatewayDelivery {
    projection: GatewayProjection,
    keys: LocalTenants,
    egress_keys: crate::LocalEgressSecrets,
}
impl GatewayDelivery {
    pub fn from_parts(
        projection: GatewayProjection,
        keys: LocalTenants,
        egress_keys: crate::LocalEgressSecrets,
    ) -> Result<Self, StoreError> {
        egress_keys.validate(&projection)?;
        if keys.network_ids().any(|net| {
            !projection
                .assignment()
                .tenants()
                .iter()
                .any(|t| t.network() == net)
        }) {
            return Err(StoreError::InvalidLocalTenants);
        }
        Ok(Self {
            projection,
            keys,
            egress_keys,
        })
    }
    pub fn into_egress_keys(self) -> crate::LocalEgressSecrets {
        self.egress_keys
    }
    pub fn projection(&self) -> &GatewayProjection {
        &self.projection
    }
    pub fn keys(&self) -> &LocalTenants {
        &self.keys
    }
    pub fn egress_keys(&self) -> &crate::LocalEgressSecrets {
        &self.egress_keys
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw<'a> {
            delivery_version: u32,
            #[serde(default, deserialize_with = "crate::egresses::present")]
            egress_private_keys: Option<crate::LocalEgressSecrets>,
            #[serde(borrow)]
            projection: &'a RawValue,
            tenant_private_keys: tenants::ReadTenants,
        }
        if bytes.len() > MAX_DELIVERY_BYTES {
            return Err(StoreError::InvalidState);
        }
        let raw: Raw<'_> = serde_json::from_slice(bytes).map_err(|_| StoreError::InvalidState)?;
        let egress_keys = match (raw.delivery_version, raw.egress_private_keys) {
            (1, None) => crate::LocalEgressSecrets::default(),
            (2, Some(keys)) => keys,
            _ => return Err(StoreError::InvalidState),
        };
        let projection = GatewayProjection::from_json(raw.projection.get())
            .map_err(StoreError::InvalidConfig)?;
        let keys = raw.tenant_private_keys.0;
        if keys.network_ids().any(|network| {
            !projection
                .assignment()
                .tenants()
                .iter()
                .any(|tenant| tenant.network() == network)
        }) {
            return Err(StoreError::InvalidLocalTenants);
        }
        egress_keys.validate(&projection)?;
        Ok(Self {
            projection,
            keys,
            egress_keys,
        })
    }
    pub(crate) fn encode(
        projection: &GatewayProjection,
        keys: &LocalTenants,
        egress_keys: &crate::LocalEgressSecrets,
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let mut bytes = Zeroizing::new(vec![0; MAX_DELIVERY_BYTES]);
        let mut out = std::io::Cursor::new(bytes.as_mut_slice());
        Self::write(&mut out, projection, keys, egress_keys)?;
        let len = out.position() as usize;
        bytes.truncate(len);
        Ok(bytes)
    }
    pub(crate) fn check_size(
        projection: &GatewayProjection,
        keys: &LocalTenants,
        egress_keys: &crate::LocalEgressSecrets,
    ) -> Result<(), StoreError> {
        struct Count(usize);
        impl std::io::Write for Count {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0 = self
                    .0
                    .checked_sub(buf.len())
                    .ok_or(std::io::ErrorKind::FileTooLarge)?;
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        Self::write(Count(MAX_DELIVERY_BYTES), projection, keys, egress_keys)
    }
    fn write(
        out: impl std::io::Write,
        projection: &GatewayProjection,
        keys: &LocalTenants,
        egress_keys: &crate::LocalEgressSecrets,
    ) -> Result<(), StoreError> {
        #[derive(Serialize)]
        struct Wire<'a> {
            delivery_version: u32,
            projection: &'a RawValue,
            tenant_private_keys: tenants::WriteTenants<'a>,
            egress_private_keys: crate::egresses::WriteEgressSecrets<'a>,
        }
        let projection =
            RawValue::from_string(projection.to_json().map_err(StoreError::InvalidConfig)?)
                .map_err(|_| StoreError::InvalidState)?;
        let wire = Wire {
            delivery_version: 2,
            egress_private_keys: crate::egresses::WriteEgressSecrets(&egress_keys.0),
            projection: &projection,
            tenant_private_keys: tenants::WriteTenants(keys),
        };
        serde_json::to_writer(out, &wire)
            .map_err(|_| StoreError::InvalidConfig(wgfeel_core::DomainError::LimitExceeded))
    }
}
