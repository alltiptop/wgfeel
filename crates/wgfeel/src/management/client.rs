use super::{paths, profile::Profile, remote};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};
use wgfeel_management::{Request, Response, http};
use zeroize::Zeroizing;
mod table;

const USAGE: &str = "usage:
  wgfeel user
  wgfeel user list
  wgfeel user show [ID]
  wgfeel user add [NAME]
  wgfeel user remove [--id ID]

  wgfeel device show [ID]
  wgfeel device add [--user ID] [--name NAME]
  wgfeel device delete [ID]

  wgfeel node list
  wgfeel node show ID
  wgfeel node add [--traffic entry|relay|off]
  wgfeel node delete ID

  wgfeel config show|identity|distribution
  wgfeel token rotate

One user is one isolated network. IDs are generated automatically.
Uses /opt/wgfeel automatically. Deletions require confirmation with y.
See wgfeel --help for all options.";
const TIMEOUT: Duration = Duration::from_secs(5);

struct Options {
    flags: BTreeMap<String, String>,
    positional: Vec<String>,
}
impl Options {
    fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        let mut flags: BTreeMap<String, String> = BTreeMap::new();
        let mut positional = Vec::new();
        let mut args = args.iter();
        while let Some(value) = args.next() {
            let value = value.to_str().ok_or(USAGE)?;
            if value.starts_with("--") {
                let next = args.next().and_then(|arg| arg.to_str()).ok_or(USAGE)?;
                if flags.insert(value.into(), next.into()).is_some() {
                    return Err("duplicate command option");
                }
            } else {
                positional.push(value.into());
            }
        }
        Ok(Self { flags, positional })
    }
    fn take(&mut self, name: &str) -> Option<String> {
        self.flags.remove(name)
    }
    fn id(&mut self) -> Result<String, &'static str> {
        if self.positional.len() != 1 {
            return Err(USAGE);
        }
        let value = self.positional.remove(0);
        valid_id(&value)?;
        Ok(value)
    }
    fn finish(self) -> Result<(), &'static str> {
        if !self.flags.is_empty() || !self.positional.is_empty() {
            return Err(USAGE);
        }
        Ok(())
    }
}
fn valid_id(value: &str) -> Result<(), &'static str> {
    wgfeel_core::ClientId::new(value)
        .map(|_| ())
        .map_err(|_| "invalid identifier")
}

fn call(
    socket: &Path,
    authorization: &str,
    method: &str,
    target: &str,
    revision: Option<u64>,
    body: &[u8],
) -> Result<Response, &'static str> {
    call_until(
        socket,
        authorization,
        method,
        target,
        revision,
        body,
        Instant::now() + TIMEOUT,
    )
}

fn call_until(
    socket: &Path,
    authorization: &str,
    method: &str,
    target: &str,
    revision: Option<u64>,
    body: &[u8],
    deadline: Instant,
) -> Result<Response, &'static str> {
    paths::socket(socket)?;
    let mut stream = paths::connect(socket).map_err(|_| "Management unavailable")?;
    let revision = revision.map(|value| format!("\"{value}\""));
    let request = http::encode_request(Request {
        method,
        target,
        authorization: (!authorization.is_empty()).then_some(authorization),
        if_match: revision.as_deref(),
        body,
    })
    .map_err(|_| "invalid Management request")?;
    let mut sent = 0;
    while sent < request.len() {
        if Instant::now() >= deadline {
            return Err("Management request timed out; inspect current revision before retry");
        }
        match stream.write(&request[sent..]) {
            Ok(0) => {
                return Err("Management request failed; inspect current revision before retry");
            }
            Ok(count) => sent += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1))
            }
            Err(_) => {
                return Err("Management request failed; inspect current revision before retry");
            }
        }
    }
    let mut input = Zeroizing::new(Vec::with_capacity(http::MAX_RESPONSE_BYTES));
    loop {
        if Instant::now() >= deadline {
            return Err("Management response timed out; inspect current revision before retry");
        }
        let mut chunk = Zeroizing::new([0u8; 8192]);
        let count = match stream.read(chunk.as_mut_slice()) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(_) => {
                return Err("Management response failed; inspect current revision before retry");
            }
        };
        if count == 0 {
            return Err("incomplete Management response; inspect current revision before retry");
        }
        if input.len() + count > http::MAX_RESPONSE_BYTES {
            return Err("Management response too large");
        }
        input.extend_from_slice(&chunk[..count]);
        match http::decode_response(&input).map_err(|_| "invalid Management response")? {
            Some(response) => return Ok(response),
            None => continue,
        }
    }
}

fn output(response: Response, title: &str) -> Result<(), &'static str> {
    if !(200..300).contains(&response.status) {
        let value =
            serde_json::from_slice(&response.body).map_err(|_| "invalid Management response")?;
        eprint!("{}", crate::output::render("Management error", &value));
        return Err("Management rejected request");
    }
    let value =
        serde_json::from_slice(&response.body).map_err(|_| "invalid Management response")?;
    print!("{}", crate::output::render(title, &value));
    Ok(())
}

struct Connection {
    socket: Option<PathBuf>,
    profile: Option<Profile>,
    authorization: Zeroizing<String>,
    installed: bool,
}
impl Connection {
    fn load(options: &mut Options, installation: &Path) -> Result<Self, &'static str> {
        let socket = options.take("--socket").map(PathBuf::from);
        let credential = options.take("--credential-file").map(PathBuf::from);
        let profile = options.take("--profile").map(PathBuf::from);
        let installed = socket.is_none() && credential.is_none() && profile.is_none();
        if !installed
            && !matches!(
                (&socket, &credential, &profile),
                (Some(_), Some(_), None) | (None, None, Some(_))
            )
        {
            return Err("choose --profile or both --socket and --credential-file");
        }
        let socket = if installed {
            Some((installation).join("instance").join("state/api.sock"))
        } else {
            socket
        };
        let profile = profile.as_deref().map(Profile::load).transpose()?;
        let authorization = if installed {
            Zeroizing::new(String::new())
        } else if let Some(profile) = &profile {
            let mut value = Zeroizing::new(String::from("Bearer "));
            STANDARD.encode_string(profile.credential()?.expose_bytes(), &mut value);
            value
        } else {
            paths::credential(credential.as_deref().ok_or(USAGE)?)?
        };
        Ok(Self {
            socket,
            profile,
            authorization,
            installed,
        })
    }
    fn call(
        &self,
        method: &str,
        target: &str,
        revision: Option<u64>,
        body: &[u8],
        deadline: Option<Instant>,
    ) -> Result<Response, &'static str> {
        if let Some(socket) = &self.socket {
            if let Some(deadline) = deadline {
                call_until(
                    socket,
                    &self.authorization,
                    method,
                    target,
                    revision,
                    body,
                    deadline,
                )
            } else {
                call(socket, &self.authorization, method, target, revision, body)
            }
        } else {
            let revision = revision.map(|value| format!("\"{value}\""));
            let profile = self.profile.as_ref().ok_or(USAGE)?;
            let request = Request {
                method,
                target,
                authorization: Some(&self.authorization),
                if_match: revision.as_deref(),
                body,
            };
            if let Some(deadline) = deadline {
                remote::call_until(profile, request, deadline)
            } else {
                remote::call(profile, request)
            }
        }
    }
}

pub(super) mod completion;
mod interactive;

pub(super) fn run(args: &[OsString]) -> Result<(), &'static str> {
    run_installed(args, &wgfeel_host::default_install_dir())
}
fn run_installed(args: &[OsString], installation: &Path) -> Result<(), &'static str> {
    run_with_io(
        args,
        installation,
        &mut io::stdin().lock(),
        &mut io::stdout().lock(),
    )
}
fn run_with_io(
    args: &[OsString],
    installation: &Path,
    input: &mut dyn io::BufRead,
    out: &mut dyn Write,
) -> Result<(), &'static str> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        let help = wgfeel_host::help::requested(args).ok_or(USAGE)?;
        return write!(out, "{help}").map_err(|_| "cannot write help");
    }
    let kind = args.first().and_then(|arg| arg.to_str()).ok_or(USAGE)?;
    let mut options = Options::parse(&args[1..])?;
    let connection = Connection::load(&mut options, installation)?;
    let installed = connection.installed;
    let call = |method: &str, target: &str, revision: Option<u64>, body: &[u8]| {
        connection.call(method, target, revision, body, None)
    };
    if kind == "user" || kind == "device" {
        return interactive::run(kind, options, &call, input, out);
    }
    let operation = if options.positional.is_empty() {
        return Err(USAGE);
    } else {
        options.positional.remove(0)
    };
    let revision = options
        .take("--revision")
        .map(|value| {
            value
                .parse::<u64>()
                .ok()
                .filter(|v| *v > 0)
                .ok_or("invalid revision")
        })
        .transpose()?;
    let invitation = kind == "node" && operation == "add";
    let mut body = Vec::new();
    if invitation && let Some(mode) = options.take("--traffic") {
        if !matches!(mode.as_str(), "entry" | "relay" | "off") {
            return Err("traffic capability must be entry, relay or off");
        }
        body = serde_json::to_vec(&serde_json::json!({"traffic": mode}))
            .map_err(|_| "cannot encode request")?;
    }
    let (method, target, title) = match (kind, operation.as_str()) {
        ("node", "add") => ("POST", "/api/v1/node-invitations".into(), "Node invitation"),
        ("token", "rotate") if installed => ("POST", "/api/v1/token/rotate".into(), "Token"),
        ("config", "show") => ("GET", "/api/v1/config".into(), "Configuration"),
        ("config", "identity") => ("GET", "/api/v1/identity".into(), "Management identity"),
        ("config", "distribution") => (
            "GET",
            "/api/v1/distribution".into(),
            "Configuration distribution",
        ),
        ("node", "list") => ("GET", "/api/v1/gateways".into(), "Nodes"),
        ("node", "show") => ("GET", format!("/api/v1/gateways/{}", options.id()?), "Node"),
        ("node", "delete") => (
            "DELETE",
            format!("/api/v1/gateways/{}", options.id()?),
            "Node deleted",
        ),
        _ => return Err(USAGE),
    };
    options.finish()?;
    if method == "GET" && revision.is_some() {
        return Err("revision is only valid for changes");
    }
    let revision = if method == "GET" {
        None
    } else {
        let current = call("GET", "/api/v1/config", None, b"")?;
        if current.status != 200 {
            return output(current, "Management error");
        }
        Some(
            revision
                .or(current.generation)
                .ok_or("Management omitted current revision")?,
        )
    };
    if method == "DELETE" {
        let current = call("GET", &target, None, b"")?;
        if current.status != 200 {
            return output(current, "Management error");
        }
        let value =
            serde_json::from_slice(&current.body).map_err(|_| "invalid Management response")?;
        write!(out, "{}", crate::output::render("Node", &value))
            .map_err(|_| "cannot write output")?;
        if !interactive::confirm(input, out, "Delete this Node?")? {
            return Ok(());
        }
    }
    let response = call(method, &target, revision, &body)?;
    if invitation && response.status == 201 {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Issued<'a> {
            invitation: &'a str,
            expires_at: u64,
            #[serde(default)]
            traffic: wgfeel_core::TrafficMode,
        }
        let issued: Issued<'_> =
            serde_json::from_slice(&response.body).map_err(|_| "invalid invitation response")?;
        let parsed = wgfeel_protocol::enrollment::Invitation::decode(issued.invitation)?;
        if parsed.expires_at() != issued.expires_at {
            return Err("invalid invitation response");
        }
        writeln!(
            out,
            "Main {} (WireGuard UDP): {}",
            parsed.management().as_str(),
            parsed
                .endpoints()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
        .map_err(|_| "cannot print invitation")?;
        writeln!(out, "Child WireGuard UDP port: {}", parsed.mesh_port())
            .map_err(|_| "cannot print invitation")?;
        // decode accepts only the URL-safe alphabet, so the quoted argument
        // cannot contain shell substitutions or terminate its single quotes.
        return writeln!(
            out,
            "Traffic capability: {}\nRun on the node (one use, valid for 15 minutes):\n\nwgfeel join '{}'",
            match issued.traffic { wgfeel_core::TrafficMode::Entry => "entry", wgfeel_core::TrafficMode::Relay => "relay", wgfeel_core::TrafficMode::Off => "off" }, issued.invitation
        )
        .map_err(|_| "cannot print invitation; create a new invitation");
    }
    if kind == "token" && response.status == 200 {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Rotated<'a> {
            token: &'a str,
        }
        let rotated: Rotated<'_> = serde_json::from_slice(&response.body)
            .map_err(|_| "invalid token rotation response")?;
        if rotated.token.len() != 44
            || STANDARD
                .decode(rotated.token)
                .map(|bytes| Zeroizing::new(bytes).len())
                .ok()
                != Some(32)
        {
            return Err("invalid token rotation response");
        }
        return writeln!(out, "{}", rotated.token)
            .map_err(|_| "token rotated but output failed; rotate again to obtain a new token");
    }
    if operation == "list" && response.status == 200 {
        return write!(out, "{}", table::render(kind, &response.body)?)
            .map_err(|_| "cannot write list");
    }
    output(response, title)
}

#[cfg(test)]
mod tests;
