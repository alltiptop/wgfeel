use super::{profile::Profile, transport::Tunnel};
use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    thread,
    time::{Duration, Instant},
};
use wgfeel_core::ServicePrivateKey;
use wgfeel_management::{Request, Response, http, tcp};

pub(super) use wgfeel_host::random_seed as seed;

pub(super) fn call(profile: &Profile, request: Request<'_>) -> Result<Response, &'static str> {
    call_cancellable(profile, request, || false)
}
pub(super) fn call_until(
    profile: &Profile,
    request: Request<'_>,
    deadline: Instant,
) -> Result<Response, &'static str> {
    call_cancellable(profile, request, || Instant::now() >= deadline)
}
fn call_cancellable(
    profile: &Profile,
    request: Request<'_>,
    cancelled: impl Fn() -> bool,
) -> Result<Response, &'static str> {
    if cancelled() {
        return Err("Management request timed out");
    }
    let endpoint = profile.endpoint();
    let listen = if endpoint.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let key = ServicePrivateKey::new(*profile.admin_private_key().expose_bytes())
        .map_err(|_| "invalid administrator identity")?;
    let mut tunnel = Tunnel::bind(
        listen,
        key,
        profile.management_id().clone(),
        profile.server_public_key().clone(),
    )?;
    exchange_on(&mut tunnel, endpoint, request, false, cancelled)
}
pub(super) fn exchange_on(
    tunnel: &mut Tunnel,
    endpoint: SocketAddr,
    request: Request<'_>,
    distribution: bool,
    cancelled: impl Fn() -> bool,
) -> Result<Response, &'static str> {
    let mut buffers = tcp::Buffers::new(1).map_err(|_| "cannot allocate service API buffers")?;
    let maximum = if distribution {
        wgfeel_store::MAX_DELIVERY_BYTES
    } else {
        wgfeel_management::MAX_REQUEST_BODY
    };
    let encoded =
        http::encode_request_with_limit(request, maximum).map_err(|_| "invalid request")?;
    let mut client = if distribution {
        tcp::Client::distribution(&mut buffers, seed()?, encoded)
    } else {
        tcp::Client::new(&mut buffers, seed()?, encoded)
    }
    .map_err(|_| "cannot initialize service API client")?;
    tunnel.initiate(endpoint)?;
    let started = Instant::now();
    let mut last_received = started;
    loop {
        if cancelled() {
            return Err("configuration delivery superseded");
        }
        if started.elapsed() >= Duration::from_secs(if distribution { 90 } else { 10 })
            || (distribution && last_received.elapsed() >= Duration::from_secs(5))
        {
            return Err("Management request timed out; inspect current revision before retry");
        }
        tunnel.poll(|packet| {
            if client.receive(packet).is_ok() {
                last_received = Instant::now();
            }
        })?;
        client
            .poll(started.elapsed())
            .map_err(|_| "Management request failed; inspect current revision before retry")?;
        while let Some(packet) = client.take_packet() {
            tunnel.send(&packet)?;
        }
        if let Some(response) = client.take_response() {
            return response
                .map_err(|_| "invalid Management response; inspect current revision before retry");
        }
        thread::sleep(Duration::from_millis(2));
    }
}
