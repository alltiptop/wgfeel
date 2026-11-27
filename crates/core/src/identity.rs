use crate::DomainError;
use serde::Serialize;
use std::fmt;
use zeroize::Zeroizing;

macro_rules! identifier {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
        #[serde(transparent)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: &str) -> Result<Self, DomainError> {
                if value.is_empty()
                    || value.len() > 64
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                {
                    return Err(DomainError::InvalidIdentifier);
                }
                Ok(Self(value.to_owned()))
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}
identifier!(NetworkId);
identifier!(ClientId);
identifier!(DeviceId);
identifier!(NodeId);

/// Structurally valid public key; possession is established by WireGuard later.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct DevicePublicKey([u8; 32]);
impl DevicePublicKey {
    pub fn new(value: [u8; 32]) -> Result<Self, DomainError> {
        if value == [0; 32] {
            return Err(DomainError::InvalidKey);
        }
        Ok(Self(value))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

macro_rules! secret {
    ($name:ident) => {
        /// Owned secret bytes with redacted diagnostics and zeroization on drop.
        /// The caller remains responsible for any copies supplied to or read from it.
        pub struct $name(Zeroizing<[u8; 32]>);
        impl $name {
            pub fn new(value: [u8; 32]) -> Result<Self, DomainError> {
                let value = Zeroizing::new(value);
                if *value == [0; 32] {
                    return Err(DomainError::InvalidKey);
                }
                Ok(Self(value))
            }
            pub fn expose_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}
secret!(AdminCredential);
secret!(InvitationToken);
secret!(ServicePrivateKey);
secret!(GatewayPrivateKey);
secret!(DevicePrivateKey);
secret!(TenantPrivateKey);

/// Permanent independent identities of one application instance. Workers receive
/// only their own key; this aggregate belongs to the protected storage boundary.
#[derive(Debug)]
pub struct NodeKeys {
    service: ServicePrivateKey,
    gateway: GatewayPrivateKey,
}
impl NodeKeys {
    pub fn new(
        service: ServicePrivateKey,
        gateway: GatewayPrivateKey,
    ) -> Result<Self, DomainError> {
        if service.expose_bytes() == gateway.expose_bytes() {
            return Err(DomainError::DuplicateGatewayKey);
        }
        Ok(Self { service, gateway })
    }
    pub fn service(&self) -> &ServicePrivateKey {
        &self.service
    }
    pub fn gateway(&self) -> &GatewayPrivateKey {
        &self.gateway
    }
    pub fn same_identity(&self, other: &Self) -> bool {
        self.service.expose_bytes() == other.service.expose_bytes()
            && self.gateway.expose_bytes() == other.gateway.expose_bytes()
    }
}
