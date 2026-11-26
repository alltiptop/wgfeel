//! External REST is a separate TCP listener, never a node control RPC endpoint.
use super::server::{ApiBudget, Connection};
use std::{
    io,
    net::{SocketAddr, TcpListener, TcpStream},
    time::Instant,
};
use wgfeel_management::{ManagementService, Request, Response};
use wgfeel_store::{RestApi, StoreError};

pub(super) const LOCAL_PATH: &str = "/local/v1/rest-api";
const MAX_CONNECTIONS: usize = 16;

pub(super) struct Listener {
    listener: Option<TcpListener>,
    connections: Vec<Connection<TcpStream>>,
    budget: ApiBudget,
}
pub(super) fn bind(settings: &RestApi) -> Result<TcpListener, &'static str> {
    let listener = TcpListener::bind(settings.listen()).map_err(|_| "cannot bind HTTP API port")?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "cannot configure HTTP API listener")?;
    Ok(listener)
}
impl Listener {
    pub(super) fn new(service: &ManagementService) -> Result<Self, &'static str> {
        let state = service
            .delivery_snapshot()
            .map_err(|_| "cannot read HTTP API settings")?;
        Ok(Self {
            listener: state.rest_api().map(bind).transpose()?,
            connections: Vec::with_capacity(MAX_CONNECTIONS),
            budget: ApiBudget::new(Instant::now()),
        })
    }
    pub(super) fn poll(&mut self, service: &mut ManagementService) -> Result<(), &'static str> {
        if let Some(listener) = &self.listener {
            for _ in 0..MAX_CONNECTIONS {
                match listener.accept() {
                    Ok((stream, _)) if self.connections.len() < MAX_CONNECTIONS => {
                        if let Ok(connection) = Connection::remote(stream) {
                            self.connections.push(connection);
                        }
                    }
                    Ok(_) => (),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err("cannot accept HTTP API connection"),
                }
            }
        }
        self.connections.retain_mut(|connection| {
            connection.progress(|request| {
                if !request.target.starts_with("/api/v1/") {
                    return Response::error(404, "not_found");
                }
                if !self.budget.allow(Instant::now()) {
                    return Response::error(429, "api_rate_limited");
                }
                // No source IP, forwarded header or loopback exemption confers owner rights.
                service.handle(request)
            })
        });
        Ok(())
    }
    /// This entry point is reachable only from the UID-authenticated Unix socket.
    pub(super) fn configure(
        &mut self,
        service: &mut ManagementService,
        request: Request<'_>,
    ) -> Response {
        if request.authorization.is_some() || request.if_match.is_some() {
            return Response::error(403, "local_owner_only");
        }
        let state = match service.delivery_snapshot() {
            Ok(state) => state,
            Err(_) => return Response::error(503, "storage_unavailable"),
        };
        if request.method == "GET" && request.body.is_empty() {
            return settings_response(state.rest_api());
        }
        if request.method != "POST" || request.body.len() > 128 {
            return Response::error(400, "invalid_rest_api_settings");
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Input {
            port: u16,
        }
        let Ok(input) = serde_json::from_slice::<Input>(request.body) else {
            return Response::error(400, "invalid_rest_api_settings");
        };
        let current = state
            .rest_api()
            .map(RestApi::listen)
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 9280)));
        let Ok(next) = RestApi::new(SocketAddr::new(current.ip(), input.port)) else {
            return Response::error(422, "invalid_http_api_port");
        };
        if state.rest_api() == Some(&next) {
            return settings_response(Some(&next));
        }
        let candidate = match bind(&next) {
            Ok(listener) => listener,
            Err(_) => return Response::error(409, "http_api_port_unavailable"),
        };
        match service.set_rest_api_local(&next) {
            Ok(()) => (),
            Err(StoreError::CommitUncertain) => {
                // Rename has published the new setting. Activate that listener
                // but do not claim durability; GET retries storage confirmation.
                self.listener = Some(candidate);
                self.connections.clear();
                return Response::error(503, "http_api_port_changed_durability_unconfirmed");
            }
            Err(_) => return Response::error(503, "http_api_settings_not_saved"),
        }
        self.listener = Some(candidate);
        self.connections.clear();
        settings_response(Some(&next))
    }
}
pub(super) fn settings_response(settings: Option<&RestApi>) -> Response {
    Response {
        status: 200,
        generation: None,
        is_config: false,
        body: serde_json::json!({"listen":settings.map(RestApi::listen)})
            .to_string()
            .into_bytes(),
    }
}
