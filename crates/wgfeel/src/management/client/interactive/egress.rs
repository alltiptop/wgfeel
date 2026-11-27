//! Operator workflows for external provider profiles, placement and user route grants.
use super::*;
use serde::{Serialize, de::DeserializeOwned};
use std::{collections::BTreeSet, net::IpAddr};
use wgfeel_core::IpPrefix;
mod policy;
mod profile_input;
use policy::{Intent, Policy};
use profile_input::Source;
use zeroize::Zeroizing;

const ROOT: &str = "/api/v1/egresses";
const REEXPORT: &str = "Re-export and re-import the affected device profiles.";
const NEED_TERMINAL: &str = "this operation requires an interactive terminal";
const SNAPSHOT_CHANGED: &str =
    "Management revision changed during selection; run the command again";

#[derive(Deserialize)]
struct Profiles {
    egresses: Vec<Profile>,
}
#[derive(Deserialize)]
struct Profile {
    id: String,
    name: String,
    node: Option<String>,
    pending_node: Option<String>,
    placement_state: String,
    #[serde(skip)]
    former_node: Option<String>,
    addresses: Vec<IpAddr>,
    allowed_ips: Vec<IpPrefix>,
}
impl Profile {
    fn label(&self) -> String {
        let placement = match self.placement_state.as_str() {
            "placed" => self.node.as_deref().unwrap_or("placed").to_owned(),
            "moving" => format!(
                "moving {} -> {}",
                self.former_node.as_deref().unwrap_or("?"),
                self.pending_node.as_deref().unwrap_or("?")
            ),
            "detaching" => format!(
                "detaching from {}",
                self.former_node.as_deref().unwrap_or("?")
            ),
            other => other.to_owned(),
        };
        format!(
            "{} ({}) — {}",
            clean(&self.name),
            clean(&self.id),
            clean(&placement)
        )
    }
}

#[derive(Clone, Deserialize)]
pub(super) struct Assignment {
    egress_id: String,
    #[serde(flatten)]
    policy: Policy,
    dormant: bool,
}
fn split_list(text: &str) -> Result<Vec<&str>> {
    let items: Vec<_> = text.split(',').map(str::trim).collect();
    if items.iter().any(|item| item.is_empty()) {
        return Err("empty item in comma-separated list");
    }
    Ok(items)
}
fn unique<T: Ord>(items: &[T]) -> Result<()> {
    if items.iter().collect::<BTreeSet<_>>().len() != items.len() {
        return Err("duplicate item in selection");
    }
    Ok(())
}
fn take_id(opts: &mut Options) -> Result<Option<String>> {
    if opts.positional.is_empty() {
        return Ok(None);
    }
    let id = opts.positional.remove(0);
    valid_id(&id)?;
    Ok(Some(id))
}
fn supplied_name(opts: &mut Options) -> Result<Option<String>> {
    let value = opts.take("--name");
    if value.as_deref().is_some_and(|n| {
        n.is_empty() || n.trim() != n || n.len() > 128 || n.chars().any(char::is_control)
    }) {
        return Err("invalid egress name");
    }
    Ok(value)
}

fn decode<T: DeserializeOwned>(response: &Response) -> Result<T> {
    serde_json::from_slice(&response.body).map_err(|_| "invalid Management response")
}
fn revision(response: &Response) -> Result<u64> {
    response.generation.ok_or("Management omitted revision")
}
fn same(expected: u64, actual: u64) -> Result<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(SNAPSHOT_CHANGED)
    }
}
impl Ui<'_> {
    fn snapshot<T: DeserializeOwned>(&mut self, path: &str) -> Result<(T, u64)> {
        let r = self.request("GET", path, None, b"")?;
        Ok((decode(&r)?, revision(&r)?))
    }
    fn write_json(
        &mut self,
        method: &str,
        path: &str,
        generation: u64,
        value: &impl Serialize,
    ) -> Result<Response> {
        // Encode into fixed zeroizing storage. Escaping config must never move a secret via realloc.
        let mut body = Zeroizing::new(vec![0; wgfeel_management::MAX_REQUEST_BODY]);
        let mut dst = &mut body[..];
        serde_json::to_writer(&mut dst, value)
            .map_err(|_| "cannot encode Management request within size limit")?;
        let used = wgfeel_management::MAX_REQUEST_BODY - dst.len();
        self.request(method, path, Some(generation), &body[..used])
    }
    fn public_output(&mut self, r: &Response, title: &str) -> Result<()> {
        let value: serde_json::Value = decode(r)?;
        write!(self.out, "{}", crate::output::render(title, &value)).map_err(|_| IO_ERROR)
    }
    fn profiles(&mut self) -> Result<(Profiles, u64)> {
        #[derive(Deserialize)]
        struct Withdrawal {
            former_node: String,
        }
        let (mut profiles, rev) = self.snapshot::<Profiles>(ROOT)?;
        for profile in &mut profiles.egresses {
            if matches!(profile.placement_state.as_str(), "moving" | "detaching") {
                let (node, observed) =
                    self.snapshot::<Withdrawal>(&format!("{ROOT}/{}/node", profile.id))?;
                same(rev, observed)?;
                profile.former_node = Some(node.former_node);
            }
        }
        Ok((profiles, rev))
    }
    fn choose_profile(&mut self, id: Option<String>) -> Result<Option<(Profile, u64)>> {
        if let Some(id) = id {
            let profile = self.snapshot(&format!("{ROOT}/{id}"))?;
            return Ok(Some(profile));
        }
        if !self.terminal {
            return Err("an egress ID is required");
        }
        let (profiles, rev) = self.profiles()?;
        for (i, p) in profiles.egresses.iter().enumerate() {
            writeln!(self.out, "{}. {}", i + 1, p.label()).map_err(|_| IO_ERROR)?;
        }
        if profiles.egresses.is_empty() {
            writeln!(self.out, "No egresses.").map_err(|_| IO_ERROR)?;
            return Ok(None);
        }
        let index = choice(self.input, self.out, profiles.egresses.len())?;
        Ok(index
            .and_then(|i| profiles.egresses.into_iter().nth(i))
            .map(|profile| (profile, rev)))
    }
    /// Enter/0 skips optional placement. EOF always cancels the enclosing operation.
    fn choose_node(&mut self, rev: u64, optional: bool) -> Result<Option<Option<String>>> {
        #[derive(Deserialize)]
        struct Nodes {
            gateways: Vec<Node>,
        }
        #[derive(Deserialize)]
        struct Node {
            recipient: String,
            traffic: String,
            endpoint: Option<std::net::SocketAddr>,
        }
        let (nodes, current) = self.snapshot::<Nodes>("/api/v1/gateways")?;
        same(rev, current)?;
        let nodes: Vec<_> = nodes
            .gateways
            .into_iter()
            .filter(|n| n.traffic == "entry" && n.endpoint.is_some())
            .collect();
        writeln!(self.out, "Select an entry node:").map_err(|_| IO_ERROR)?;
        for (i, n) in nodes.iter().enumerate() {
            writeln!(self.out, "{}. {} (entry)", i + 1, clean(&n.recipient))
                .map_err(|_| IO_ERROR)?;
        }
        let prompt = if optional {
            "0. none — save on main\nSelect node [0]: "
        } else {
            "0. cancel\nSelect node [0]: "
        };
        let Some(value) = line(self.input, self.out, prompt)? else {
            return Ok(None);
        };
        if value.is_empty() || value == "0" {
            return Ok(optional.then_some(None));
        }
        let i = value
            .parse::<usize>()
            .ok()
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| nodes.get(i))
            .ok_or("invalid entry node selection")?;
        valid_id(&i.recipient)?;
        Ok(Some(Some(i.recipient.clone())))
    }
    fn choose_users(&mut self, rev: u64) -> Result<Option<Vec<String>>> {
        let (users, current) = self.users()?;
        same(rev, current)?;
        for (i, u) in users.iter().enumerate() {
            writeln!(self.out, "{}. {} ({})", i + 1, clean(&u.name), clean(&u.id))
                .map_err(|_| IO_ERROR)?;
        }
        let Some(value) = line(
            self.input,
            self.out,
            "0. none\nSelect users (comma-separated) [0]: ",
        )?
        else {
            return Ok(None);
        };
        if value.is_empty() || value == "0" {
            return Ok(Some(vec![]));
        }
        let ids = split_list(&value)?
            .into_iter()
            .map(|n| {
                n.parse::<usize>()
                    .ok()
                    .and_then(|i| i.checked_sub(1))
                    .and_then(|i| users.get(i))
                    .map(|u| u.id.clone())
                    .ok_or("invalid user selection")
            })
            .collect::<Result<Vec<_>>>()?;
        unique(&ids)?;
        Ok(Some(ids))
    }
}

impl Ui<'_> {
    fn add_egress(&mut self, mut opts: Options) -> Result<()> {
        let name = supplied_name(&mut opts)?;
        let mut node = opts.take("--node");
        if let Some(n) = &node {
            valid_id(n)?
        }
        let mut users = opts
            .take("--users")
            .map(|v| -> Result<Vec<String>> {
                let ids = split_list(&v)?
                    .into_iter()
                    .map(|id| {
                        valid_id(id)?;
                        Ok(id.to_owned())
                    })
                    .collect::<Result<Vec<_>>>()?;
                unique(&ids)?;
                Ok(ids)
            })
            .transpose()?;
        let intent = Intent::parse(&mut opts)?;
        let source = Source::parse(&mut opts)?;
        opts.finish()?;
        if !self.terminal && users.is_some() && node.is_none() {
            return Err("--users requires --node");
        }
        if !self.terminal && users.is_none() && intent.supplied() {
            return Err("route and DNS options require users");
        }
        let Some(raw) = source.read(self)? else {
            return Ok(());
        };
        let config = std::str::from_utf8(&raw).map_err(|_| "invalid WireGuard profile")?;
        let profile = wgfeel_management::preview_egress_profile(config)
            .map_err(|_| "invalid WireGuard profile")?;
        let name = match name {
            Some(value) => value,
            None if self.terminal => {
                let Some(value) = line(
                    self.input,
                    self.out,
                    &format!("Enter egress name [{}]: ", profile.name),
                )?
                else {
                    return Ok(());
                };
                if value.is_empty() {
                    profile.name.clone()
                } else {
                    value
                }
            }
            None => profile.name.clone(),
        };
        if name.len() > 128 || name.chars().any(char::is_control) {
            return Err("invalid egress name");
        }
        let (_, rev) = self.snapshot::<Profiles>(ROOT)?;
        if node.is_none() && self.terminal {
            let Some(value) = self.choose_node(rev, users.is_none())? else {
                return Ok(());
            };
            node = value;
        }
        if node.is_some() && users.is_none() && self.terminal {
            let Some(value) = self.choose_users(rev)? else {
                return Ok(());
            };
            users = Some(value);
        }
        let users = users.unwrap_or_default();
        #[derive(Serialize)]
        struct Grant<'a> {
            user: &'a str,
            #[serde(flatten)]
            policy: &'a Policy,
        }
        #[derive(Serialize)]
        struct Import<'a> {
            config: &'a str,
            name: &'a str,
            node: Option<&'a str>,
            users: Vec<Grant<'a>>,
        }
        let policy = if users.is_empty() {
            if intent.supplied() {
                return Err("route and DNS options require users");
            }
            None
        } else {
            let Some(policy) = intent.policy(self, &profile.addresses, &profile.allowed_ips)?
            else {
                return Ok(());
            };
            writeln!(
                self.out,
                "Users {} | {}",
                users.join(", "),
                policy.description()
            )
            .map_err(|_| IO_ERROR)?;
            Some(policy)
        };
        let grants = policy
            .as_ref()
            .map(|policy| users.iter().map(|u| Grant { user: u, policy }).collect())
            .unwrap_or_default();
        let result = self.write_json(
            "POST",
            ROOT,
            rev,
            &Import {
                config,
                name: &name,
                node: node.as_deref(),
                users: grants,
            },
        )?;
        self.public_output(&result, "Egress added")?;
        if policy.is_some() {
            writeln!(self.out, "{REEXPORT}").map_err(|_| IO_ERROR)?
        }
        Ok(())
    }
    fn replace_egress(
        &mut self,
        id: &str,
        rev: u64,
        name: Option<String>,
        source: Source,
    ) -> Result<()> {
        let Some(raw) = source.read(self)? else {
            return Ok(());
        };
        let config = std::str::from_utf8(&raw).map_err(|_| "invalid WireGuard profile")?;
        wgfeel_management::preview_egress_profile(config)
            .map_err(|_| "invalid WireGuard profile")?;
        #[derive(Serialize)]
        struct Replacement<'a> {
            config: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            name: Option<&'a str>,
        }
        let r = self.write_json(
            "PUT",
            &format!("{ROOT}/{id}"),
            rev,
            &Replacement {
                config,
                name: name.as_deref(),
            },
        )?;
        self.public_output(&r, "Egress replaced")?;
        writeln!(
            self.out,
            "If the provider DNS changed, re-export and re-import the affected device profiles."
        )
        .map_err(|_| IO_ERROR)
    }
    fn remove_egress(&mut self, profile: &Profile, rev: u64) -> Result<bool> {
        if !self.terminal {
            return Err(NEED_TERMINAL);
        }
        if !confirm(
            self.input,
            self.out,
            &format!("Delete egress {}?", profile.label()),
        )? {
            return Ok(false);
        }
        self.request("DELETE", &format!("{ROOT}/{}", profile.id), Some(rev), b"")?;
        writeln!(self.out, "Egress deleted: {}", clean(&profile.id)).map_err(|_| IO_ERROR)?;
        Ok(true)
    }
    fn show_placement(&mut self, id: &str, rev: u64) -> Result<()> {
        let r = self.request("GET", &format!("{ROOT}/{id}/node"), None, b"")?;
        same(rev, revision(&r)?)?;
        self.public_output(&r, "Egress placement")
    }
    fn place(&mut self, id: &str, node: Option<&str>, rev: u64) -> Result<Response> {
        self.write_json(
            "PUT",
            &format!("{ROOT}/{id}/node"),
            rev,
            &serde_json::json!({"node":node}),
        )
    }
    fn unassign(&mut self, profile: &Profile, rev: u64) -> Result<()> {
        if !confirm(
            self.input,
            self.out,
            &format!("Unassign {}?", profile.label()),
        )? {
            return Ok(());
        }
        let response = self.place(&profile.id, None, rev)?;
        self.public_output(&response, "Egress placement")
    }
    fn details_menu(&mut self, id: &str) -> Result<()> {
        loop {
            let r = self.request("GET", &format!("{ROOT}/{id}"), None, b"")?;
            let rev = revision(&r)?;
            let profile: Profile = decode(&r)?;
            self.public_output(&r, "Egress")?;
            if matches!(profile.placement_state.as_str(), "moving" | "detaching") {
                self.show_placement(id, rev)?
            }
            writeln!(
                self.out,
                "1. assign / move node\n2. unassign node\n3. replace config\n4. delete"
            )
            .map_err(|_| IO_ERROR)?;
            match choice(self.input, self.out, 4)? {
                Some(0) => {
                    if let Some(Some(node)) = self.choose_node(rev, false)? {
                        let r = self.place(id, Some(&node), rev)?;
                        self.public_output(&r, "Egress placement")?;
                    }
                }
                Some(1) => self.unassign(&profile, rev)?,
                Some(2) => self.replace_egress(id, rev, None, Source::default())?,
                Some(3) => {
                    if self.remove_egress(&profile, rev)? {
                        return Ok(());
                    }
                }
                _ => return Ok(()),
            }
        }
    }
    fn egress_home(&mut self) -> Result<()> {
        if !self.terminal {
            return Err(NEED_TERMINAL);
        }
        loop {
            writeln!(
                self.out,
                "1. add egress\n2. list egresses\n3. delete egress"
            )
            .map_err(|_| IO_ERROR)?;
            match choice(self.input, self.out, 3)? {
                Some(0) => self.add_egress(Options::default())?,
                Some(1) => {
                    if let Some((p, _)) = self.choose_profile(None)? {
                        self.details_menu(&p.id)?
                    }
                }
                Some(2) => {
                    if let Some((p, r)) = self.choose_profile(None)? {
                        self.remove_egress(&p, r)?;
                    }
                }
                _ => return Ok(()),
            }
        }
    }
    fn list_assignments(&mut self, id: &str) -> Result<(Vec<Assignment>, u64)> {
        #[derive(Deserialize)]
        struct Assignments {
            egresses: Vec<Assignment>,
        }
        let (list, rev) = self.snapshot::<Assignments>(&format!("/api/v1/users/{id}/egresses"))?;
        self.describe_assignments(&list.egresses, rev)?;
        Ok((list.egresses, rev))
    }
    pub(super) fn describe_assignments(&mut self, list: &[Assignment], rev: u64) -> Result<()> {
        if list.is_empty() {
            return writeln!(self.out, "No egress assignments.").map_err(|_| IO_ERROR);
        }
        let (profiles, r) = self.profiles()?;
        same(rev, r)?;
        for (i, a) in list.iter().enumerate() {
            let p = profiles
                .egresses
                .iter()
                .find(|p| p.id == a.egress_id)
                .ok_or("assigned profile missing")?;
            writeln!(
                self.out,
                "{}. {}{} | {}",
                i + 1,
                p.label(),
                if a.dormant { " (dormant)" } else { "" },
                a.policy.description()
            )
            .map_err(|_| IO_ERROR)?;
        }
        Ok(())
    }
    fn user_ref(&mut self, supplied: Option<String>) -> Result<Option<(String, Option<u64>)>> {
        if let Some(user) = supplied {
            return Ok(Some((user, None)));
        }
        if !self.terminal {
            return Err("a user ID is required");
        }
        Ok(self.select_user(None)?.map(|(u, r)| (u.id, Some(r))))
    }
    fn set_grant(
        &mut self,
        user: &str,
        id: Option<String>,
        node: Option<String>,
        intent: Intent,
        selected_revision: Option<u64>,
    ) -> Result<()> {
        let Some((p, mut rev)) = self.choose_profile(id)? else {
            return Ok(());
        };
        if let Some(previous) = selected_revision {
            same(rev, previous)?
        }
        let attach = match p.placement_state.as_str() {
            "placed" if node.is_some() => {
                return Err("use wgfeel egress node to move a placed egress");
            }
            "placed" => None,
            "unassigned" => {
                if node.is_some() {
                    node
                } else if self.terminal {
                    writeln!(self.out, "Egress {} is unassigned.", clean(&p.id))
                        .map_err(|_| IO_ERROR)?;
                    let Some(node) = self.choose_node(rev, false)? else {
                        return Ok(());
                    };
                    node
                } else {
                    return Err("unassigned egress requires --node");
                }
            }
            "moving" | "detaching" => {
                self.show_placement(&p.id, rev)?;
                return Err("egress is awaiting withdrawal from its former node");
            }
            _ => return Err("invalid placement state"),
        };
        let Some(policy) = intent.policy(self, &p.addresses, &p.allowed_ips)? else {
            return Ok(());
        };
        writeln!(self.out, "{} | {}", p.label(), policy.description()).map_err(|_| IO_ERROR)?;
        if let Some(node) = &attach {
            // A mistyped user ID must be caught before committing shared node placement.
            if selected_revision.is_none() {
                let r = self.request("GET", &format!("/api/v1/users/{user}"), None, b"")?;
                same(rev, revision(&r)?)?;
            }
            let r = self.place(&p.id, Some(node), rev)?;
            if r.status != 200 {
                return Err(
                    "egress placement is pending; inspect placement before assigning users",
                );
            }
            rev = revision(&r)?;
        }
        let target = format!("/api/v1/users/{user}/egresses/{}", p.id);
        let body = serde_json::to_vec(&policy).map_err(|_| "cannot encode user assignment")?;
        let reply = (self.api)("PUT", &target, Some(rev), &body);
        let rejected = reply.as_ref().is_ok_and(|r| (400..500).contains(&r.status));
        let result = reply.and_then(|r| self.accept(r));
        if let (Some(node), Err(_)) = (&attach, &result) {
            if rejected {
                writeln!(
                    self.out,
                    "Egress attached to {}. User assignment was not saved.",
                    clean(node)
                )
                .map_err(|_| IO_ERROR)?;
            } else {
                writeln!(
                    self.out,
                    "Egress attached to {}. Inspect the current user assignment before retrying.",
                    clean(node)
                )
                .map_err(|_| IO_ERROR)?;
            }
        }
        result?;
        writeln!(self.out, "Assignment saved. {REEXPORT}").map_err(|_| IO_ERROR)
    }
    fn remove_grant(
        &mut self,
        user: &str,
        id: Option<String>,
        selected_revision: Option<u64>,
    ) -> Result<()> {
        if !self.terminal {
            return Err(NEED_TERMINAL);
        }
        let (assignments, rev) = self.list_assignments(user)?;
        if let Some(r) = selected_revision {
            same(r, rev)?
        }
        let assignment = if let Some(id) = id {
            assignments
                .iter()
                .find(|a| a.egress_id == id)
                .ok_or("user assignment not found")?
        } else {
            if assignments.is_empty() {
                return Ok(());
            }
            let Some(i) = choice(self.input, self.out, assignments.len())? else {
                return Ok(());
            };
            &assignments[i]
        };
        let id = &assignment.egress_id;
        if confirm(
            self.input,
            self.out,
            &format!("Remove egress {} from user {}?", clean(id), clean(user)),
        )? {
            self.request(
                "DELETE",
                &format!("/api/v1/users/{user}/egresses/{id}"),
                Some(rev),
                b"",
            )?;
            writeln!(self.out, "Assignment removed. {REEXPORT}").map_err(|_| IO_ERROR)?;
        }
        Ok(())
    }
    pub(super) fn user_egress_menu(&mut self, user: &str) -> Result<()> {
        if !self.terminal {
            return Err(NEED_TERMINAL);
        }
        loop {
            let (_, rev) = self.list_assignments(user)?;
            writeln!(
                self.out,
                "1. add / edit egress assignment\n2. remove egress assignment"
            )
            .map_err(|_| IO_ERROR)?;
            match choice(self.input, self.out, 2)? {
                Some(0) => self.set_grant(user, None, None, Intent::default(), Some(rev))?,
                Some(1) => self.remove_grant(user, None, Some(rev))?,
                _ => return Ok(()),
            }
        }
    }
}

pub(super) fn run(ui: &mut Ui<'_>, mut opts: Options, user_command: bool) -> Result<()> {
    let op = if opts.positional.is_empty() {
        String::new()
    } else {
        opts.positional.remove(0)
    };
    let noninteractive = opts.take("--non-interactive").is_some();
    ui.terminal &= !noninteractive && !opts.flags.contains_key("--config-stdin");
    if user_command {
        let user = take_id(&mut opts)?;
        let egress = if matches!(op.as_str(), "set" | "remove") {
            take_id(&mut opts)?
        } else {
            None
        };
        let (node, intent) = if op == "set" {
            let n = opts.take("--node");
            if let Some(id) = &n {
                valid_id(id)?
            }
            (n, Intent::parse(&mut opts)?)
        } else {
            (None, Intent::default())
        };
        opts.finish()?;
        if !matches!(op.as_str(), "list" | "set" | "remove") {
            return Err(USAGE);
        }
        let Some((user, selected)) = ui.user_ref(user)? else {
            return Ok(());
        };
        match op.as_str() {
            "list" => {
                ui.list_assignments(&user)?;
                Ok(())
            }
            "set" => ui.set_grant(&user, egress, node, intent, selected),
            "remove" => ui.remove_grant(&user, egress, selected),
            _ => unreachable!(),
        }
    } else {
        match op.as_str() {
            "" => {
                opts.finish()?;
                ui.egress_home()
            }
            "add" => ui.add_egress(opts),
            "list" => {
                opts.finish()?;
                let (profiles, _) = ui.profiles()?;
                if profiles.egresses.is_empty() {
                    writeln!(ui.out, "No egresses.").map_err(|_| IO_ERROR)?
                }
                for p in profiles.egresses {
                    writeln!(ui.out, "{}", p.label()).map_err(|_| IO_ERROR)?
                }
                Ok(())
            }
            "show" | "node" | "replace" | "delete" => {
                let id = take_id(&mut opts)?;
                let node = if op == "node" {
                    opts.take("--node")
                } else {
                    None
                };
                if let Some(id) = &node {
                    valid_id(id)?
                }
                let unassign = op == "node" && opts.take("--unassign").is_some();
                if node.is_some() && unassign {
                    return Err("choose --node or --unassign");
                }
                let name = if op == "replace" {
                    supplied_name(&mut opts)?
                } else {
                    None
                };
                let source = if op == "replace" {
                    Some(Source::parse(&mut opts)?)
                } else {
                    None
                };
                opts.finish()?;
                if (op == "delete" || unassign) && !ui.terminal {
                    return Err(NEED_TERMINAL);
                }
                if op == "show"
                    && let Some(id) = &id
                {
                    let r = ui.request("GET", &format!("{ROOT}/{id}"), None, b"")?;
                    return ui.public_output(&r, "Egress");
                }
                let Some((p, rev)) = ui.choose_profile(id)? else {
                    return Ok(());
                };
                match op.as_str() {
                    "show" => {
                        let r = ui.request("GET", &format!("{ROOT}/{}", p.id), None, b"")?;
                        same(rev, revision(&r)?)?;
                        ui.public_output(&r, "Egress")
                    }
                    "replace" => ui.replace_egress(&p.id, rev, name, source.unwrap()),
                    "delete" => {
                        ui.remove_egress(&p, rev)?;
                        Ok(())
                    }
                    "node" if unassign => ui.unassign(&p, rev),
                    "node" if node.is_some() => {
                        let r = ui.place(&p.id, node.as_deref(), rev)?;
                        ui.public_output(&r, "Egress placement")
                    }
                    "node" => ui.show_placement(&p.id, rev),
                    _ => unreachable!(),
                }
            }
            _ => Err(USAGE),
        }
    }
}

#[cfg(test)]
mod tests;
