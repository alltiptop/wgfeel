//! Strict data-only import of one WireGuard interface and provider peer.
use super::{ApiError, generated_id, models::*, operations::Context};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::net::IpAddr;
use wgfeel_core::*;
use wgfeel_store::EgressKeys;

#[derive(Default)]
struct Fields<'a> {
    private: Option<&'a str>,
    public: Option<&'a str>,
    preshared: Option<&'a str>,
    endpoint: Option<&'a str>,
    mtu: Option<&'a str>,
    keepalive: Option<&'a str>,
    addresses: Vec<IpAddr>,
    dns: Vec<IpAddr>,
    allowed: Vec<IpPrefix>,
}
fn add_list<T>(
    out: &mut Vec<T>,
    value: &str,
    limit: usize,
    parse: impl Fn(&str) -> Result<T, DomainError>,
) -> Result<(), DomainError> {
    for item in value.split(',') {
        if out.len() >= limit {
            return Err(DomainError::LimitExceeded);
        }
        out.push(parse(item.trim())?);
    }
    Ok(())
}

fn host_address(value: &str) -> Result<IpAddr, DomainError> {
    let ip = if let Some((ip, _)) = value.split_once('/') {
        value.parse::<IpPrefix>()?;
        ip
    } else {
        value
    };
    ip.parse().map_err(|_| DomainError::InvalidAddress)
}
fn number(value: &str) -> Result<u16, DomainError> {
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(DomainError::InvalidEgress);
    }
    value.parse().map_err(|_| DomainError::InvalidEgress)
}
impl<'a> Fields<'a> {
    fn parse(config: &'a str) -> Result<Self, DomainError> {
        if config.len() > MAX_PROFILE_BYTES {
            return Err(DomainError::LimitExceeded);
        }
        let mut fields = Self::default();
        let (mut interface_seen, mut peer_seen) = (false, false);
        let mut section = "";
        for line in config.lines() {
            let line = line.split_once('#').map_or(line, |(text, _)| text).trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') {
                match line {
                    "[Interface]" if !interface_seen => interface_seen = true,
                    "[Peer]" if !peer_seen => peer_seen = true,
                    _ => return Err(DomainError::InvalidEgress),
                }
                section = line;
                continue;
            }
            let (field, value) = line.split_once('=').ok_or(DomainError::InvalidEgress)?;
            let value = value.trim();
            let scalar = match (section, field.trim()) {
                ("[Interface]", "Address") => {
                    add_list(&mut fields.addresses, value, 2, host_address)?;
                    continue;
                }
                ("[Interface]", "DNS") => {
                    add_list(&mut fields.dns, value, MAX_DNS_SERVERS_PER_EGRESS, |ip| {
                        ip.parse().map_err(|_| DomainError::InvalidAddress)
                    })?;
                    continue;
                }
                ("[Peer]", "AllowedIPs") => {
                    add_list(
                        &mut fields.allowed,
                        value,
                        MAX_ALLOWED_IPS_PER_EGRESS,
                        str::parse,
                    )?;
                    continue;
                }
                ("[Interface]", "PrivateKey") => &mut fields.private,
                ("[Interface]", "MTU") => &mut fields.mtu,
                ("[Peer]", "PublicKey") => &mut fields.public,
                ("[Peer]", "PresharedKey") => &mut fields.preshared,
                ("[Peer]", "Endpoint") => &mut fields.endpoint,
                ("[Peer]", "PersistentKeepalive") => &mut fields.keepalive,
                _ => return Err(DomainError::InvalidEgress),
            };
            if scalar.replace(value).is_some() {
                return Err(DomainError::InvalidEgress);
            }
        }
        Ok(fields)
    }
}

fn import(
    id: EgressId,
    name: Option<String>,
    config: &str,
) -> Result<(EgressProfile, EgressKeys), DomainError> {
    let fields = Fields::parse(config)?;
    let decode = |text| wgfeel_protocol::decode_key(text).map_err(|_| DomainError::InvalidKey);
    let peer_public_key =
        DevicePublicKey::new(*decode(fields.public.ok_or(DomainError::InvalidKey)?)?)?;
    let private = EgressPrivateKey::new(*decode(fields.private.ok_or(DomainError::InvalidKey)?)?)?;
    let preshared = fields
        .preshared
        .map(|v| PresharedKey::new(*decode(v)?))
        .transpose()?;
    let keys = EgressKeys::new(private, preshared);
    let endpoint: EgressEndpoint = fields
        .endpoint
        .ok_or(DomainError::InvalidAddress)?
        .parse()?;
    let keepalive = match fields.keepalive {
        None | Some("off") => None,
        Some(raw) => std::num::NonZeroU16::new(number(raw)?),
    };
    let profile = EgressProfileFields {
        node: None,
        pending_node: None,
        id,
        name: name.unwrap_or_else(|| endpoint.default_name().to_owned()),
        secret_revision: 1,
        interface_public_key: keys.interface_public_key(&peer_public_key)?,
        addresses: fields.addresses,
        dns_servers: fields.dns,
        mtu: fields.mtu.map(number).transpose()?,
        peer_public_key,
        endpoint,
        allowed_ips: fields.allowed,
        persistent_keepalive: keepalive,
        has_preshared_key: fields.preshared.is_some(),
    };
    Ok((profile.try_into()?, keys))
}

/// Parse the same provider metadata used by the atomic import transaction.
pub fn preview_egress_profile(config: &str) -> Result<EgressProfile, DomainError> {
    import(EgressId::new("preview")?, None, config).map(|(profile, _)| profile)
}
fn profile<'a>(doc: &'a ManagementDocument, id: &EgressId) -> Result<&'a EgressProfile, ApiError> {
    doc.routing()
        .egress_policy()
        .profile(id)
        .ok_or(ApiError(404, "not_found"))
}

fn placement(doc: &ManagementDocument, p: &EgressProfile) -> EgressNode {
    let reservation = doc
        .routing()
        .egress_policy()
        .reservation(&p.interface_public_key);
    let placement_state = if p.node.is_some() {
        PlacementState::Placed
    } else if p.pending_node.is_some() {
        PlacementState::Moving
    } else if reservation.is_some() {
        PlacementState::Detaching
    } else {
        PlacementState::Unassigned
    };
    EgressNode {
        egress_id: p.id.clone(),
        node: p.node.clone(),
        pending_node: p.pending_node.clone(),
        placement_state,
        former_node: reservation.map(|r| r.former_node.clone()),
        withdrawal_generation: reservation.map(|r| r.removal_generation),
    }
}

fn view(doc: &ManagementDocument, p: &EgressProfile) -> Egress {
    Egress {
        id: p.id.clone(),
        name: p.name.clone(),
        node: p.node.clone(),
        pending_node: p.pending_node.clone(),
        placement_state: placement(doc, p).placement_state,
        interface_public_key: STANDARD.encode(p.interface_public_key.as_bytes()),
        peer_public_key: STANDARD.encode(p.peer_public_key.as_bytes()),
        addresses: p.addresses.clone(),
        dns_servers: p.dns_servers.clone(),
        mtu: p.mtu,
        endpoint: p.endpoint.clone(),
        allowed_ips: p.allowed_ips.clone(),
        persistent_keepalive: p.persistent_keepalive,
        has_preshared_key: p.has_preshared_key,
    }
}

fn eligible_node(doc: &ManagementDocument, node: Option<&NodeId>) -> Result<(), ApiError> {
    if let Some(id) = node {
        let assignment = doc
            .routing()
            .assignments()
            .iter()
            .find(|a| a.recipient() == id)
            .ok_or(ApiError(404, "not_found"))?;
        if !assignment.traffic().accepts_devices() || assignment.endpoint().is_none() {
            return Err(ApiError(422, "invalid_egress_node"));
        }
    }
    Ok(())
}
fn user_id(doc: &ManagementDocument, user: &str) -> Result<ClientId, ApiError> {
    let id = ClientId::new(user)?;
    doc.clients()
        .iter()
        .any(|u| u.id() == &id)
        .then_some(id)
        .ok_or(ApiError(404, "not_found"))
}
pub(super) fn assignment_list(doc: &ManagementDocument, user: &ClientId) -> AssignmentList {
    let policy = doc.routing().egress_policy();
    AssignmentList {
        egresses: policy
            .grants(user)
            .iter()
            .map(|grant| AssignmentView {
                dormant: policy
                    .profile(&grant.egress_id)
                    .is_none_or(|p| p.node.is_none()),
                grant: grant.clone(),
            })
            .collect(),
    }
}

impl Context<'_> {
    pub fn create_egress(&mut self, input: AddEgress<'_>) -> Result<ChangeReceipt, ApiError> {
        if input.node.is_none() && !input.users.is_empty() {
            return Err(DomainError::EgressNodeRequired.into());
        }
        let config = decode_config(input.config)?;
        self.change(|doc, secrets| {
            eligible_node(doc, input.node.as_ref())?;
            let id = EgressId::new(&format!("eg_{}", generated_id(None)?))?;
            let (p, keys) = import(id.clone(), input.name, &config)?;
            let users = input
                .users
                .into_iter()
                .map(|g| {
                    (
                        g.user,
                        UserEgressAssignment {
                            egress_id: id.clone(),
                            routes: g.routes,
                            dns: g.dns,
                        },
                    )
                })
                .collect();
            secrets.insert_egress(id.clone(), keys)?;
            Ok((
                ManagementChange::AddEgress {
                    profile: Box::new(p.with_placement(input.node, None)?),
                    users,
                },
                id.as_str().into(),
            ))
        })
    }
    pub fn list_egresses(&self) -> Result<Egresses, ApiError> {
        let doc = self.state.document();
        Ok(Egresses {
            egresses: doc
                .routing()
                .egresses()
                .iter()
                .map(|p| view(doc, p))
                .collect(),
        })
    }
    pub fn get_egress(&self, id: &str) -> Result<Egress, ApiError> {
        let doc = self.state.document();
        Ok(view(doc, profile(doc, &EgressId::new(id)?)?))
    }
    pub fn replace_egress(
        &mut self,
        id: &str,
        input: ReplaceEgress<'_>,
    ) -> Result<Egress, ApiError> {
        let id = EgressId::new(id)?;
        let (_, doc) = self.change_document(|doc, secrets| {
            let old = profile(doc, &id)?;
            if old.pending_node.is_some() {
                return Err(DomainError::EgressMovePending.into());
            }
            let config = decode_config(input.config)?;
            let (p, keys) = import(
                id.clone(),
                Some(input.name.unwrap_or_else(|| old.name.clone())),
                &config,
            )?;
            let changed = secrets.replace_egress(&id, keys)?;
            let revision = old
                .secret_revision
                .checked_add(u64::from(changed))
                .ok_or(DomainError::InvalidGeneration)?;
            Ok((
                ManagementChange::ReplaceEgress(Box::new(p.with_secret_revision(revision)?)),
                id.as_str().into(),
            ))
        })?;
        Ok(view(&doc, profile(&doc, &id)?))
    }
    pub fn get_egress_node(&self, id: &str) -> Result<EgressNode, ApiError> {
        let doc = self.state.document();
        Ok(placement(doc, profile(doc, &EgressId::new(id)?)?))
    }
    pub fn set_egress_node(
        &mut self,
        id: &str,
        input: SetEgressNode,
    ) -> Result<EgressNode, ApiError> {
        let id = EgressId::new(id)?;
        let previous = self.revision;
        let (_, doc) = self.change_document(|doc, _| {
            profile(doc, &id)?;
            eligible_node(doc, input.node.as_ref())?;
            Ok((
                ManagementChange::SetEgressNode {
                    egress: id.clone(),
                    node: input.node,
                },
                id.as_str().into(),
            ))
        })?;
        let result = placement(&doc, profile(&doc, &id)?);
        if self.revision != previous && result.former_node.is_some() {
            self.status = Some(202)
        }
        Ok(result)
    }
    pub fn delete_egress(&mut self, id: &str) -> Result<ChangeReceipt, ApiError> {
        self.change(|_, _| {
            Ok((
                ManagementChange::RemoveEgress(EgressId::new(id)?),
                id.to_owned(),
            ))
        })
    }
    pub fn get_user_egresses(&self, user: &str) -> Result<AssignmentList, ApiError> {
        let doc = self.state.document();
        Ok(assignment_list(doc, &user_id(doc, user)?))
    }
    pub fn set_user_egresses(
        &mut self,
        user: &str,
        input: GrantSet,
    ) -> Result<AssignmentList, ApiError> {
        let user = user_id(self.state.document(), user)?;
        let (_, doc) = self.change_document(|doc, _| {
            for grant in &input.egresses {
                profile(doc, &grant.egress_id)?;
            }
            Ok((
                ManagementChange::SetUserEgresses {
                    user: user.clone(),
                    egresses: input.egresses,
                },
                user.as_str().into(),
            ))
        })?;
        Ok(assignment_list(&doc, &user))
    }
    pub fn set_user_egress(
        &mut self,
        user: &str,
        id: &str,
        input: GrantInput,
    ) -> Result<AssignmentView, ApiError> {
        let doc = self.state.document();
        let owner = user_id(doc, user)?;
        let id = EgressId::new(id)?;
        let mut egresses = doc.routing().egress_policy().grants(&owner).to_vec();
        let assignment = UserEgressAssignment {
            egress_id: id.clone(),
            routes: input.routes,
            dns: input.dns,
        };
        if let Some(old) = egresses.iter_mut().find(|g| g.egress_id == id) {
            *old = assignment
        } else {
            egresses.push(assignment)
        }
        self.set_user_egresses(user, GrantSet { egresses })?
            .egresses
            .into_iter()
            .find(|v| v.grant.egress_id == id)
            .ok_or(ApiError(500, "invalid_user_context"))
    }
    pub fn delete_user_egress(&mut self, user: &str, id: &str) -> Result<ChangeReceipt, ApiError> {
        self.change(|doc, _| {
            let user = user_id(doc, user)?;
            let mut egresses = doc.routing().egress_policy().grants(&user).to_vec();
            let i = egresses
                .iter()
                .position(|g| g.egress_id.as_str() == id)
                .ok_or(ApiError(404, "not_found"))?;
            egresses.remove(i);
            Ok((
                ManagementChange::SetUserEgresses { user, egresses },
                id.to_owned(),
            ))
        })
    }
}

// RawValue borrows the validated JSON token from the bounded request body.
// Deserializing an escaped JSON string normally copies the entire decoded
// profile into serde_json's growable, non-zeroizing scratch allocation.
fn decode_config(
    raw: &serde_json::value::RawValue,
) -> Result<zeroize::Zeroizing<String>, ApiError> {
    let mut text = raw
        .get()
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or(ApiError(400, "invalid_json"))?;
    let mut decoded =
        zeroize::Zeroizing::new(String::with_capacity(text.len().min(MAX_PROFILE_BYTES)));
    loop {
        let (plain, escaped) = text
            .split_once('\\')
            .map_or((text, None), |(plain, rest)| (plain, Some(rest)));
        if plain.len() > MAX_PROFILE_BYTES - decoded.len() {
            return Err(ApiError(422, "invalid_egress"));
        }
        decoded.push_str(plain);
        let Some(rest) = escaped else {
            return Ok(decoded);
        };
        let (ch, tail) = decode_escape(rest).ok_or(ApiError(400, "invalid_json"))?;
        if ch.len_utf8() > MAX_PROFILE_BYTES - decoded.len() {
            return Err(ApiError(422, "invalid_egress"));
        }
        decoded.push(ch);
        text = tail;
    }
}

fn decode_escape(rest: &str) -> Option<(char, &str)> {
    fn code_unit(s: &str) -> Option<(u16, &str)> {
        let (digits, tail) = s.split_at_checked(4)?;
        Some((u16::from_str_radix(digits, 16).ok()?, tail))
    }
    let (escape, tail) = rest.split_at_checked(1)?;
    let ch = match escape {
        "u" => {
            let (first, tail) = code_unit(tail)?;
            if (0xd800..=0xdbff).contains(&first) {
                let (second, tail) = code_unit(tail.strip_prefix("\\u")?)?;
                let ch = char::decode_utf16([first, second]).next()?.ok()?;
                return Some((ch, tail));
            }
            return Some((char::from_u32(u32::from(first))?, tail));
        }
        "\"" => '"',
        "\\" => '\\',
        "/" => '/',
        "b" => '\u{8}',
        "f" => '\u{c}',
        "n" => '\n',
        "r" => '\r',
        "t" => '\t',
        _ => return None,
    };
    Some((ch, tail))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::value::RawValue;

    #[test]
    fn config_decoding_preserves_json_characters_and_counts_decoded_bytes() {
        let raw = r##""# comment \"\\\/\b\f\r\n\t\u0041\uD83D\uDD10""##;
        let token = serde_json::from_str::<&RawValue>(raw).unwrap();
        let decoded = decode_config(token).ok().unwrap();
        assert_eq!(&*decoded, &serde_json::from_str::<String>(raw).unwrap());
        for (len, accepted) in [(MAX_PROFILE_BYTES, true), (MAX_PROFILE_BYTES + 1, false)] {
            let raw = format!("\"{}\"", "\\u0061".repeat(4) + &"b".repeat(len - 4));
            let token = serde_json::from_str::<&RawValue>(&raw).unwrap();
            assert_eq!(decode_config(token).is_ok(), accepted);
        }
    }
}
