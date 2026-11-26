//! Explicit owner-only configuration for the independent HTTP integration API.
use super::{paths, rest};
use std::{
    ffi::OsString,
    io::{self, Read, Write},
    net::SocketAddr,
    path::PathBuf,
    time::Duration,
};
use wgfeel_protocol::{Request, Response, http};
use wgfeel_store::{ManagementStore, RestApi};

const USAGE: &str = "usage: wgfeel api port [PORT] [--state-dir PATH] [--install-dir PATH]";
pub(crate) fn run(args: &[OsString]) -> Result<(), String> {
    if args.first().is_none_or(|arg| arg != "port") {
        return Err(USAGE.into());
    }
    let mut port = None;
    let mut state = None;
    let mut install = None;
    let mut args = args[1..].iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--state-dir") if state.is_none() => {
                state = Some(PathBuf::from(args.next().ok_or(USAGE)?))
            }
            Some("--install-dir") if install.is_none() => {
                install = Some(PathBuf::from(args.next().ok_or(USAGE)?))
            }
            Some(value) if port.is_none() && !value.starts_with('-') => {
                port = Some(
                    value
                        .parse::<u16>()
                        .ok()
                        .filter(|port| *port != 0)
                        .ok_or("HTTP API port must be 1..65535")?,
                );
            }
            _ => return Err(USAGE.into()),
        }
    }
    if state.is_some() && install.is_some() {
        return Err("choose --state-dir or --install-dir".into());
    }
    let state = match state {
        Some(state) => state,
        None => install
            .unwrap_or_else(wgfeel_host::default_install_dir)
            .join("instance")
            .join("state"),
    };
    let socket = state.join("api.sock");
    // A valid private directory is required even if the service is stopped.
    paths::parent(&socket)?;
    match std::fs::symlink_metadata(&socket) {
        Ok(_) => paths::socket(&socket)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(_) => return Err("cannot inspect the protected local main API".into()),
    }
    let response = match paths::connect(&socket) {
        Ok(mut stream) => {
            if rustix::net::sockopt::socket_peercred(&stream)
                .map_err(|_| "cannot verify local main identity")?
                .uid
                != rustix::process::geteuid()
            {
                return Err("unexpected local main identity".into());
            }
            stream
                .set_nonblocking(false)
                .map_err(|_| "cannot configure local API connection")?;
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .map_err(|_| "cannot configure local API timeout")?;
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .map_err(|_| "cannot configure local API timeout")?;
            let body = port
                .map(|port| serde_json::json!({"port":port}).to_string())
                .unwrap_or_default();
            let encoded = http::encode_request(Request {
                method: if port.is_some() { "POST" } else { "GET" },
                target: rest::LOCAL_PATH,
                authorization: None,
                if_match: None,
                body: body.as_bytes(),
            })
            .map_err(|_| "cannot encode HTTP API settings")?;
            stream
                .write_all(&encoded)
                .map_err(|_| "cannot send HTTP API settings")?;
            let mut bytes = Vec::new();
            stream
                .take(8193)
                .read_to_end(&mut bytes)
                .map_err(|_| "cannot read HTTP API settings")?;
            if bytes.len() > 8192 {
                return Err("invalid local API response".into());
            }
            http::decode_response(&bytes)
                .map_err(|_| "invalid local API response")?
                .ok_or("incomplete local API response")?
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            let mut store = ManagementStore::open(&state)
                .map_err(|_| "cannot open main state; the service may still be running")?;
            let current = store
                .load()
                .map_err(|_| "cannot read main state")?
                .ok_or("main is not initialized")?;
            if let Some(port) = port {
                let address = current
                    .rest_api()
                    .map(RestApi::listen)
                    .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 9280)));
                let next = RestApi::new(SocketAddr::new(address.ip(), port))
                    .map_err(|_| "invalid HTTP API settings")?;
                let _reservation = rest::bind(&next)?;
                store
                    .set_rest_api(&next)
                    .map_err(|error| format!("cannot save HTTP API settings: {error}"))?;
                rest::settings_response(Some(&next))
            } else {
                rest::settings_response(current.rest_api())
            }
        }
        Err(_) => return Err("cannot connect to the protected local main API".into()),
    };
    print_settings(response)
}
fn print_settings(response: Response) -> Result<(), String> {
    if response.status != 200 {
        let body: serde_json::Value =
            serde_json::from_slice(&response.body).map_err(|_| "invalid local API response")?;
        let message = match body["error"].as_str() {
            Some("http_api_port_unavailable") => {
                "HTTP API port is unavailable; the previous listener is unchanged"
            }
            Some("http_api_port_changed_durability_unconfirmed") => {
                "HTTP API port changed but durability is unconfirmed; run wgfeel api port to inspect it"
            }
            _ => "HTTP API settings could not be changed; inspect them with wgfeel api port",
        };
        return Err(message.into());
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Settings {
        listen: Option<SocketAddr>,
    }
    let settings: Settings =
        serde_json::from_slice(&response.body).map_err(|_| "invalid local API response")?;
    match settings.listen {
        Some(address) => println!("HTTP API: http://{address}"),
        None => println!("HTTP API is not configured."),
    }
    Ok(())
}
