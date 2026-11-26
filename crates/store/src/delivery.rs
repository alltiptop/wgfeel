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
}
impl GatewayDelivery {
    pub fn projection(&self) -> &GatewayProjection {
        &self.projection
    }
    pub fn keys(&self) -> &LocalTenants {
        &self.keys
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw<'a> {
            delivery_version: u32,
            #[serde(borrow)]
            projection: &'a RawValue,
            tenant_private_keys: tenants::ReadTenants,
        }
        if bytes.len() > MAX_DELIVERY_BYTES {
            return Err(StoreError::InvalidState);
        }
        let raw: Raw<'_> = serde_json::from_slice(bytes).map_err(|_| StoreError::InvalidState)?;
        if raw.delivery_version != 1 {
            return Err(StoreError::InvalidState);
        }
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
        Ok(Self { projection, keys })
    }
    pub(crate) fn encode(
        projection: &GatewayProjection,
        keys: &LocalTenants,
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        #[derive(Serialize)]
        struct Wire<'a> {
            delivery_version: u32,
            projection: &'a RawValue,
            tenant_private_keys: tenants::WriteTenants<'a>,
        }
        let projection =
            RawValue::from_string(projection.to_json().map_err(StoreError::InvalidConfig)?)
                .map_err(|_| StoreError::InvalidState)?;
        let wire = Wire {
            delivery_version: 1,
            projection: &projection,
            tenant_private_keys: tenants::WriteTenants(keys),
        };
        let mut bytes = Zeroizing::new(vec![0; MAX_DELIVERY_BYTES]);
        let mut writer = std::io::Cursor::new(bytes.as_mut_slice());
        serde_json::to_writer(&mut writer, &wire).map_err(|_| StoreError::InvalidState)?;
        let len = writer.position() as usize;
        bytes.truncate(len);
        Ok(bytes)
    }
}
