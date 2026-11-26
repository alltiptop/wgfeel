use std::{
    ffi::OsString,
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};
use wgfeel_protocol::{Request, enrollment::Invitation};
use zeroize::Zeroizing;
pub(crate) const PATH: &str = "/internal/v1/join";
const USAGE: &str = "wgfeel join INVITATION [--endpoint IP:PORT] [--install-dir PATH]";

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Contact,
    ReverseProof,
    Registration,
    Configuration,
}
impl Phase {
    pub fn waiting(self) -> &'static str {
        match self {
            Self::Contact => "Waiting for main to accept the invitation claim",
            Self::ReverseProof => {
                "Main accepted the claim. Waiting for its WireGuard probe on the advertised child endpoint"
            }
            Self::Registration => {
                "Child received the authenticated probe. Waiting for main to confirm registration"
            }
            Self::Configuration => {
                "Main registered the child. Waiting for configuration to be applied and saved"
            }
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Failure {
    NoClaimReply,
    NoProbe,
    NoRegistration,
    NoConfiguration,
    LocalSetup,
    Rejected,
    InvitationClaimed,
    IdentityConflict,
}
impl Failure {
    pub fn message(self) -> &'static str {
        match self {
            Self::NoClaimReply => {
                "join timed out waiting for an authenticated reply from main to the invitation claim"
            }
            Self::NoProbe => {
                "join timed out after main accepted the claim; child received no authenticated WireGuard probe on its advertised endpoint"
            }
            Self::NoRegistration => {
                "join timed out after child received the WireGuard probe; main did not confirm registration"
            }
            Self::NoConfiguration => {
                "join timed out after registration; child could not confirm a durably applied configuration"
            }
            Self::LocalSetup => "join failed while preparing the local enrollment transport",
            Self::Rejected => "main rejected the enrollment request",
            Self::InvitationClaimed => {
                "main rejected this attempt because the invitation was already claimed; issue a fresh invitation with wgfeel node add"
            }
            Self::IdentityConflict => {
                "main rejected a conflicting child identity; check the node name and existing registration on main"
            }
        }
    }
}

pub(super) fn run(args: &[OsString]) -> Result<(), &'static str> {
    let Some(uri) = args.first().and_then(|arg| arg.to_str()) else {
        return Err(USAGE);
    };
    let invitation = Invitation::decode(uri)?;
    let mut state = wgfeel_host::default_install_dir()
        .join("instance")
        .join("state");
    let mut endpoints: Vec<SocketAddr> = vec![];
    if !(args.len() - 1).is_multiple_of(2) {
        return Err(USAGE);
    }
    for pair in args[1..].as_chunks::<2>().0 {
        match pair[0].to_str() {
            Some("--install-dir") => state = PathBuf::from(&pair[1]).join("instance").join("state"),
            Some("--state-dir") => state = PathBuf::from(&pair[1]),
            Some("--endpoint") => {
                endpoints.push(pair[1].to_str().ok_or(USAGE)?.parse().map_err(|_| USAGE)?)
            }
            _ => return Err(USAGE),
        }
    }
    let installed = wgfeel_host::install::child_settings(&state)?;
    if let Some(settings) = &installed
        && endpoints.is_empty()
    {
        endpoints.extend(
            settings
                .addresses
                .iter()
                .map(|ip| SocketAddr::new(*ip, invitation.mesh_port())),
        );
    }
    wgfeel_core::validate_node_endpoints(&endpoints).map_err(|_| "invalid node endpoints")?;
    #[derive(serde::Serialize)]
    struct Input<'a> {
        invitation: &'a str,
        endpoints: &'a [SocketAddr],
    }
    let body = Zeroizing::new(
        serde_json::to_vec(&Input {
            invitation: uri,
            endpoints: &endpoints,
        })
        .map_err(|_| "cannot encode join request")?,
    );
    let mut progress = io::stderr().lock();
    writeln!(
        progress,
        "Connecting to Manager {} via UDP: {} ...",
        invitation.management().as_str(),
        invitation
            .endpoints()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    )
    .map_err(|_| "cannot write join progress")?;
    let socket = state.join("api.sock");
    if let Some(settings) = installed {
        match super::local::connect(&socket) {
            Ok(_) => (),
            Err("node service is not running" | "node service is unavailable") => {
                if endpoints.is_empty()
                    || endpoints
                        .iter()
                        .any(|addr| addr.port() != invitation.mesh_port())
                {
                    return Err("installed child endpoints must use the UDP port assigned by main");
                }
                let listen = SocketAddr::new(settings.listen_ip, invitation.mesh_port());
                writeln!(
                    progress,
                    "Enrolling on UDP port {}. Waiting for main to confirm and send configuration.",
                    listen.port()
                )
                .map_err(|_| "cannot write join progress")?;
                drop(progress);
                super::runtime::foreground(
                    &[
                        "--state-dir".into(),
                        state.as_os_str().into(),
                        "--listen".into(),
                        listen.to_string().into(),
                    ],
                    Some(&body),
                )?;
                if settings.start_after_join {
                    wgfeel_host::install::activate_child(&state)?;
                }
                println!(
                    "Node joined Manager {}. Configuration saved. {}",
                    invitation.management().as_str(),
                    if settings.start_after_join {
                        "Service enabled and started."
                    } else {
                        "Service is stopped (--no-start)."
                    }
                );
                return Ok(());
            }
            Err(error) => return Err(error),
        }
    }
    drop(invitation);
    let response = super::local::exchange(
        &socket,
        Request {
            method: "POST",
            target: PATH,
            authorization: None,
            if_match: None,
            body: &body,
        },
    )?;
    if response.status == 409
        && serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .is_some_and(|v| v["error"] == "stop_child_before_changing_mesh_port")
    {
        return Err(
            "the new main assigns a different UDP port; stop wgfeel.service and retry join",
        );
    }
    if response.status != 202 {
        return Err("node rejected join; verify the invitation and service state");
    }
    let value: serde_json::Value =
        serde_json::from_slice(&response.body).map_err(|_| "invalid join response")?;
    let operation = value["operation"].as_u64().ok_or("invalid join response")?;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(75);
    let mut next_progress = started + Duration::from_secs(5);
    writeln!(
        progress,
        "Local Node accepted the join request. Waiting for Manager confirmation and configuration (timeout: 75s)."
    )
    .map_err(|_| "cannot write join progress")?;
    loop {
        if Instant::now() >= deadline {
            return Err("join timed out; check node state before retrying");
        }
        let response = super::local::exchange(
            &socket,
            Request {
                method: "GET",
                target: PATH,
                authorization: None,
                if_match: None,
                body: b"",
            },
        )?;
        let value: serde_json::Value =
            serde_json::from_slice(&response.body).map_err(|_| "invalid join status")?;
        if value["operation"].as_u64() != Some(operation) {
            return Err("join operation was superseded");
        }
        match value["state"].as_str() {
            Some("applied") => {
                println!(
                    "Node joined Manager {}. Configuration saved.",
                    value["management"].as_str().ok_or("invalid join status")?
                );
                return Ok(());
            }
            Some("failed") => {
                return Err(
                    serde_json::from_value::<Failure>(value["failure"].clone()).map_or(
                        "join failed; check the child service status",
                        Failure::message,
                    ),
                );
            }
            Some("pending") => {
                let now = Instant::now();
                if now >= next_progress {
                    writeln!(
                        progress,
                        "{} ({}s elapsed).",
                        serde_json::from_value::<Phase>(value["phase"].clone()).map_or(
                            "Still waiting for Manager confirmation and configuration",
                            Phase::waiting
                        ),
                        now.duration_since(started).as_secs()
                    )
                    .map_err(|_| "cannot write join progress")?;
                    next_progress = now + Duration::from_secs(5);
                }
            }
            _ => return Err("invalid join status"),
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}
