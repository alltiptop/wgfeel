use super::{ApiError, ManagementService, generated_id, models::*, provision, storage_error};
use base64::{Engine, engine::general_purpose::STANDARD};
use wgfeel_core::*;
use wgfeel_store::{ManagementSecrets, StoredManagement};

pub(super) struct Context<'a> {
    pub service: &'a mut ManagementService,
    pub state: &'a StoredManagement,
    pub revision: u64,
    pub status: Option<u16>,
}

impl<'a> Context<'a> {
    pub fn list_users(&self) -> Result<Users<'a>, ApiError> {
        let document = self.state.document();
        Ok(Users {
            users: document
                .clients()
                .iter()
                .map(|user| user_view(document, user))
                .collect(),
        })
    }
    pub fn get_user(&self, user: &str) -> Result<User<'a>, ApiError> {
        Ok(user_view(self.state.document(), self.user(user)?))
    }
    pub(super) fn user(&self, id: &str) -> Result<&'a Client, ApiError> {
        self.state
            .document()
            .clients()
            .iter()
            .find(|user| user.id().as_str() == id)
            .ok_or(ApiError(404, "not_found"))
    }
    pub fn list_devices(&self, user: &str) -> Result<Devices<'a>, ApiError> {
        Ok(Devices {
            devices: self.user(user)?.devices(),
        })
    }
    pub fn get_device(&self, user: &str, device: &str) -> Result<&'a ClientDevice, ApiError> {
        self.user(user)?
            .devices()
            .iter()
            .find(|entry| entry.id().as_str() == device)
            .ok_or(ApiError(404, "not_found"))
    }
    pub fn list_gateways(&self) -> Result<Gateways<'a>, ApiError> {
        let document = self.state.document();
        Ok(Gateways {
            gateways: document
                .routing()
                .assignments()
                .iter()
                .map(|gateway| gateway_view(document, gateway))
                .collect(),
        })
    }
    pub fn get_gateway(&self, gateway: &str) -> Result<Gateway<'a>, ApiError> {
        let document = self.state.document();
        let node = document
            .routing()
            .assignments()
            .iter()
            .find(|entry| entry.recipient().as_str() == gateway)
            .ok_or(ApiError(404, "not_found"))?;
        Ok(gateway_view(document, node))
    }
    pub fn get_identity(&self) -> Result<Identity<'a>, ApiError> {
        let public = aws_lc_rs::agreement::PrivateKey::from_private_key(
            &aws_lc_rs::agreement::X25519,
            self.state.service_private_key().expose_bytes(),
        )
        .map_err(|_| ApiError(503, "identity_unavailable"))?
        .compute_public_key()
        .map_err(|_| ApiError(503, "identity_unavailable"))?;
        Ok(Identity {
            management_id: self.state.document().routing().management_id(),
            public_key: STANDARD.encode(public.as_ref()),
        })
    }
    pub fn get_distribution(&self) -> Result<Distribution<'a>, ApiError> {
        let gateways = self
            .state
            .document()
            .routing()
            .assignments()
            .iter()
            .chain(self.state.retired_gateways())
            .map(|node| {
                let acknowledged = self.service.delivered.get(node.recipient()).copied();
                GatewayDelivery {
                    id: node.recipient(),
                    desired: self.revision,
                    acknowledged,
                    status: if node.endpoint().is_none() {
                        DeliveryStatus::Unconfigured
                    } else if acknowledged == Some(self.revision) {
                        DeliveryStatus::Applied
                    } else {
                        DeliveryStatus::Pending
                    },
                }
            })
            .collect();
        Ok(Distribution {
            generation: self.revision,
            gateways,
        })
    }

    pub fn issue_invitation(
        &mut self,
        input: InvitationOptions,
    ) -> Result<IssuedInvitation, ApiError> {
        self.service.issue_invitation(self.state, input)
    }
    pub fn rotate_token(&mut self) -> Result<RotatedToken, ApiError> {
        let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
        aws_lc_rs::rand::fill(bytes.as_mut_slice())
            .map_err(|_| ApiError(503, "randomness_unavailable"))?;
        let credential =
            AdminCredential::new(*bytes).map_err(|_| ApiError(503, "randomness_unavailable"))?;
        let token = zeroize::Zeroizing::new(STANDARD.encode(credential.expose_bytes()));
        self.service
            .store
            .rotate_admin_credential(&credential)
            .map_err(storage_error)?;
        Ok(RotatedToken { token })
    }
    pub fn create_user(&mut self, input: AddUser) -> Result<ChangeReceipt, ApiError> {
        self.change(|_, _| {
            let id = generated_id(None)?;
            Ok((
                ManagementChange::AddClient {
                    client: ClientId::new(&id)?,
                    network: NetworkId::new(&id)?,
                    name: input.name,
                },
                id,
            ))
        })
    }
    pub fn delete_user(&mut self, user: &str) -> Result<ChangeReceipt, ApiError> {
        self.change(|_, _| {
            Ok((
                ManagementChange::RemoveClient {
                    client: ClientId::new(user)?,
                },
                user.into(),
            ))
        })
    }
    pub fn suspend_user(&mut self, user: &str, _: EmptyObject) -> Result<ChangeReceipt, ApiError> {
        self.set_suspended(user, true)
    }
    pub fn resume_user(&mut self, user: &str, _: EmptyObject) -> Result<ChangeReceipt, ApiError> {
        self.set_suspended(user, false)
    }
    fn set_suspended(&mut self, user: &str, suspended: bool) -> Result<ChangeReceipt, ApiError> {
        self.change(|_, _| {
            Ok((
                ManagementChange::SetClientSuspended {
                    client: ClientId::new(user)?,
                    suspended,
                },
                user.into(),
            ))
        })
    }
    pub fn create_device(
        &mut self,
        user: &str,
        input: AddDevice,
    ) -> Result<ChangeReceipt, ApiError> {
        self.change(|doc, secrets| provision::device(doc, secrets, user, input))
    }
    pub fn delete_device(&mut self, user: &str, device: &str) -> Result<ChangeReceipt, ApiError> {
        self.change(|_, _| {
            Ok((
                ManagementChange::RemoveDevice {
                    client: ClientId::new(user)?,
                    device: DeviceId::new(device)?,
                },
                device.into(),
            ))
        })
    }
    pub fn create_gateway(&mut self, input: AddGateway) -> Result<ChangeReceipt, ApiError> {
        self.change(|doc, _| add_gateway(doc, input))
    }
    pub fn delete_gateway(&mut self, gateway: &str) -> Result<ChangeReceipt, ApiError> {
        self.change(|_, _| {
            Ok((
                ManagementChange::RemoveGateway {
                    gateway: NodeId::new(gateway)?,
                },
                gateway.into(),
            ))
        })
    }

    pub(super) fn change(
        &mut self,
        build: impl FnOnce(
            &ManagementDocument,
            &mut ManagementSecrets,
        ) -> Result<(ManagementChange, String), ApiError>,
    ) -> Result<ChangeReceipt, ApiError> {
        self.change_document(build).map(|(receipt, _)| receipt)
    }

    pub(super) fn change_document(
        &mut self,
        build: impl FnOnce(
            &ManagementDocument,
            &mut ManagementSecrets,
        ) -> Result<(ManagementChange, String), ApiError>,
    ) -> Result<(ChangeReceipt, ManagementDocument), ApiError> {
        let document = self.state.document();
        let mut secrets = self.state.secrets().copy_owned().map_err(storage_error)?;
        let (change, id) = build(document, &mut secrets)?;
        let next = provision::apply_change(document, self.revision, &change, &mut secrets)?;
        if next.routing().generation() == self.revision {
            return Ok((
                ChangeReceipt {
                    id,
                    generation: self.revision,
                    distribution: ChangeDistribution::Pending,
                },
                next,
            ));
        }
        self.service
            .store
            .commit_with_verifier(
                &next,
                self.state.node_keys(),
                self.state.admin_verifier(),
                &secrets,
                Some(self.revision),
            )
            .map_err(storage_error)?;
        self.revision = next.routing().generation();
        Ok((
            ChangeReceipt {
                id,
                generation: self.revision,
                distribution: ChangeDistribution::Pending,
            },
            next,
        ))
    }
}

fn user_view<'a>(document: &ManagementDocument, client: &'a Client) -> User<'a> {
    User {
        id: client.id(),
        name: client.name(),
        egresses: super::egress::assignment_list(document, client.id()).egresses,
        suspended: document
            .routing()
            .config()
            .networks()
            .iter()
            .any(|network| network.id() == client.network() && network.suspended()),
        devices: client.devices(),
    }
}

fn gateway_view<'a>(
    document: &'a ManagementDocument,
    gateway: &'a GatewayAssignment,
) -> Gateway<'a> {
    let owner = |network: &NetworkId| {
        document
            .clients()
            .iter()
            .find(|client| client.network() == network)
            .map(Client::id)
    };
    Gateway {
        recipient: gateway.recipient(),
        service_public_key: gateway.service_public_key(),
        gateway_public_key: gateway.gateway_public_key(),
        endpoint: gateway.endpoint(),
        endpoints: gateway.endpoints(),
        hostname: gateway.hostname(),
        auto_users: gateway.auto_networks(),
        traffic: gateway.traffic(),
        users: gateway.networks().iter().map(owner).collect(),
        tenants: gateway
            .tenants()
            .iter()
            .map(|tenant| GatewayTenant {
                user: owner(tenant.network()),
                public_key: tenant.public_key(),
            })
            .collect(),
    }
}

pub(super) fn public_key(value: &str) -> Result<DevicePublicKey, ApiError> {
    let bytes = super::decode_key(value).map_err(|_| ApiError(422, "invalid_public_key"))?;
    DevicePublicKey::new(*bytes).map_err(Into::into)
}

fn add_gateway(
    document: &ManagementDocument,
    mut value: AddGateway,
) -> Result<(ManagementChange, String), ApiError> {
    if !value.users.is_empty() && !value.networks.is_empty() {
        return Err(ApiError(422, "conflicting_scope"));
    }
    let user_network = |id: &str| -> Result<NetworkId, ApiError> {
        document
            .clients()
            .iter()
            .find(|client| client.id().as_str() == id)
            .map(|client| client.network().clone())
            .ok_or(ApiError(422, "unknown_user"))
    };
    for user in &value.users {
        value.networks.push(user_network(user)?.as_str().to_owned());
    }
    let automatic = value.auto_networks.unwrap_or(
        value.endpoint.is_some() && value.networks.is_empty() && value.tenants.is_empty(),
    );
    let id = generated_id(value.id)?;
    let tenants = value
        .tenants
        .into_iter()
        .map(|tenant| {
            Ok(TenantKeyAssignment::new(
                match (tenant.user, tenant.network) {
                    (Some(user), None) => user_network(&user)?,
                    (None, Some(network)) => NetworkId::new(&network)?,
                    _ => return Err(ApiError(422, "invalid_tenant")),
                },
                public_key(&tenant.public_key)?,
            ))
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok((
        ManagementChange::AddGateway {
            assignment: GatewayAssignment::new(
                NodeId::new(&id)?,
                public_key(&value.public_key)?,
                public_key(&value.gateway_public_key)?,
                value
                    .networks
                    .into_iter()
                    .map(|network| NetworkId::new(&network))
                    .collect::<Result<_, _>>()?,
                tenants,
            )?
            .with_endpoint(value.endpoint)?
            .with_traffic(value.traffic)?
            .with_auto_networks(automatic),
        },
        id,
    ))
}
