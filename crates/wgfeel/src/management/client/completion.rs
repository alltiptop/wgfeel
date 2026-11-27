//! Only public IDs and names are returned; no ordinary CLI dispatch or prompts.
use super::{Connection, Options, Response};
use serde::Deserialize;
use std::time::{Duration, Instant};
use wgfeel_host::help::completion::{Candidate, Completion, Entity};

pub(crate) fn complete(request: &Completion) -> Vec<Candidate> {
    query(request).unwrap_or_default()
}

fn query(request: &Completion) -> Result<Vec<Candidate>, &'static str> {
    let started = Instant::now();
    let entity = request.entity.ok_or("missing entity")?;
    let mut options = Options::parse(&request.connection)?;
    let connection = Connection::load(&mut options, &wgfeel_host::default_install_dir())?;
    options.finish()?;
    // A remote request establishes a fresh WireGuard/TCP session. Allow its
    // initial retransmission; keep local socket completion on the shorter budget.
    let deadline = started
        + if connection.profile.is_some() {
            Duration::from_secs(3)
        } else {
            Duration::from_millis(500)
        };
    let target = match entity {
        Entity::Users | Entity::Devices | Entity::UserList => "/api/v1/users",
        Entity::Nodes | Entity::EntryNodes => "/api/v1/gateways",
        Entity::Egresses => "/api/v1/egresses",
    };
    // The method and paths are fixed here. No user-provided operation is run.
    let response = connection.call("GET", target, None, b"", Some(deadline))?;
    candidates(entity, &request.prefix, response)
}

#[derive(Deserialize)]
struct User {
    id: String,
    name: String,
    devices: Vec<Device>,
}
#[derive(Deserialize)]
struct Device {
    id: String,
    metadata: Metadata,
}
#[derive(Deserialize)]
struct Metadata {
    name: Option<String>,
}
#[derive(Deserialize)]
struct Node {
    recipient: String,
    hostname: Option<String>,
    traffic: Option<String>,
    endpoint: Option<String>,
}

fn candidates(
    entity: Entity,
    prefix: &str,
    response: Response,
) -> Result<Vec<Candidate>, &'static str> {
    if response.status != 200 || response.is_config {
        return Err("completion unavailable");
    }
    let mut candidates = Vec::new();
    let (previous, partial) = if entity == Entity::UserList {
        prefix
            .rsplit_once(',')
            .map_or(("", prefix), |(head, tail)| {
                (&prefix[..head.len() + 1], tail)
            })
    } else {
        ("", prefix)
    };
    if let Some(ids) = previous.strip_suffix(',')
        && ids
            .split(',')
            .any(|id| wgfeel_core::ClientId::new(id).is_err() || id.starts_with("--"))
    {
        return Ok(candidates);
    }
    let mut add = |id: String, name: String| {
        // IDs are inserted as arguments, while names are only display labels.
        if !id.starts_with("--")
            && id.starts_with(partial)
            && !previous.split(',').any(|used| used == id)
            && wgfeel_core::ClientId::new(&id).is_ok()
        {
            candidates.push(Candidate::new(format!("{previous}{id}"), name));
        }
    };
    match entity {
        Entity::Users | Entity::Devices | Entity::UserList => {
            #[derive(Deserialize)]
            struct Users {
                users: Vec<User>,
            }
            let users: Users = serde_json::from_slice(&response.body)
                .map_err(|_| "invalid completion response")?;
            for user in users.users {
                if entity != Entity::Devices {
                    add(user.id, user.name);
                } else {
                    for device in user.devices {
                        add(
                            device.id,
                            format!(
                                "{} / {}",
                                user.name,
                                device.metadata.name.as_deref().unwrap_or("Unnamed device")
                            ),
                        );
                    }
                }
            }
        }
        Entity::Egresses => {
            #[derive(Deserialize)]
            struct Egress {
                id: String,
                name: String,
            }
            #[derive(Deserialize)]
            struct Profiles {
                egresses: Vec<Egress>,
            }
            let list: Profiles = serde_json::from_slice(&response.body)
                .map_err(|_| "invalid completion response")?;
            for p in list.egresses {
                add(p.id, p.name)
            }
        }
        Entity::EntryNodes | Entity::Nodes => {
            #[derive(Deserialize)]
            struct Nodes {
                gateways: Vec<Node>,
            }
            let nodes: Nodes = serde_json::from_slice(&response.body)
                .map_err(|_| "invalid completion response")?;
            for node in nodes.gateways {
                if entity == Entity::EntryNodes
                    && (node.traffic.as_deref() != Some("entry") || node.endpoint.is_none())
                {
                    continue;
                }
                add(
                    node.recipient,
                    node.hostname.unwrap_or_else(|| "Node".into()),
                );
            }
        }
    }
    candidates.sort_by(|a, b| a.value.cmp(&b.value));
    candidates.dedup_by(|a, b| a.value == b.value);
    candidates.truncate(4096);
    Ok(candidates)
}
