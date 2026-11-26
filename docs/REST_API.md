# External REST API

The REST API is an HTTP/TCP listener on main for web-panel backends and other
integrations. It is separate from the internal WireGuard/UDP node-control
protocol. Internal enrollment and configuration RPC paths are not exposed over
HTTP. See the [node model](ARCHITECTURE.md).
Remote CLI profiles use an authenticated WireGuard connection to the same UDP
listener as the mesh. HTTP integrations use the separate REST listener and an
administrator bearer token.

Nodes connect to main through service WireGuard on the shared UDP port, including
their initial enrollment, key verification and configuration delivery. These
operations work with the HTTP listener disabled. An administrator may issue an
invitation through REST, but the child consumes it using WireGuard, never HTTP.

## Configure the listener

Interactive installation asks for the external HTTP port. The default is `9280`,
bound to `127.0.0.1`. Noninteractive installation accepts `--api-port PORT` and
`--api-listen-ip IP`. The low-level `init --control main` command enables HTTP only
when `--api-port` is supplied.

Show the configured address or change the port locally on main:

```sh
wgfeel api port
wgfeel api port 8081
```

The running service opens the new port, saves the setting, and closes the old
listener. If the new port is unavailable, the previous listener and stored
configuration remain unchanged. This operation does not restart or reconfigure
WireGuard. If the service is stopped, it saves the port for the next start after
checking that it can be bound. An uncertain disk commit is reported as an error;
inspect the current setting with `wgfeel api port` before retrying.

`--install-dir PATH` selects a custom installation. `--state-dir PATH` selects
an explicitly initialized main state directory instead. Changing this setting
requires the local state owner's permissions; it is not a remotely callable REST
operation.

## Authentication and requests

Issue an administrator token locally with `wgfeel token rotate`. The command
prints the new token once and invalidates the previous token. wgfeel stores its
verifier, not the clear-text token. Keep the token in the integration's protected
configuration and send it as an `Authorization: Bearer ...` header.

Even loopback HTTP requests require a token. Forwarded headers do not bypass
authentication. The default loopback listener is suitable for a local web-panel
backend or a TLS reverse proxy. Direct HTTP provides no transport encryption.

For example, a panel backend can read users with this HTTP/1.1 request:

```http
GET /api/v1/users HTTP/1.1
Host: localhost:9280
Authorization: Bearer YOUR_TOKEN
Connection: close
```

Successful administrative responses carry an `ETag` with the configuration
revision. Configuration mutations and token rotation require the matching
`If-Match` header: a missing header receives `428`, a malformed revision `400`, and
a stale revision `412`.

`POST /api/v1/node-invitations` creates a temporary invitation without changing
the configuration revision. Its `If-Match` header is optional, but when supplied
it must match the current revision (the same `400`/`412` errors apply). This checks
the revision at issuance; it does not reserve that revision for later enrollment.

JSON POST requests require `Content-Type: application/json` and `Content-Length`.
Requests and connection lifetimes are bounded; rate-limited requests receive `429`.

Available administrative resources include `/api/v1/users`, user devices,
`/api/v1/gateways`, `/api/v1/config`, node invitations and token rotation. Device
configuration responses contain private keys and must be treated as secrets.
The API is intended for an authenticated integration backend; browser sessions,
cookies and CORS are not implemented by this listener.

`GET /api/v1/users/{user}/devices/{device}/config` returns the WireGuard text
shown by `wgfeel device show`. Each entry Node serving the user's network is
labelled with its hostname and ID, or just its ID when no hostname is available.
Each Node has its own `[Peer]` section with a public key and one preferred
`Endpoint`. Endpoints are grouped by IPv4 and IPv6, with alternative addresses
in comments. Only the device's assigned Node has `AllowedIPs` and
`PersistentKeepalive`. Routing traffic through a different Node requires
assigning the device to it and importing the updated configuration.

Manual `POST /api/v1/gateways` registration requires both `public_key` (service)
and `gateway_public_key` (mesh), encoded in base64. They must be distinct. Normal
enrollment obtains these from the node through a one-time invitation. Public
configuration responses name them `service_public_key` and `gateway_public_key`.

[README](../README.md) · [Command reference](docs.md) · [Security policy](SECURITY.md)
