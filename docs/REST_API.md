# External HTTP REST API

`main` runs an optional HTTP/1.1 TCP listener for web panels and external
integrations. It is separate from the internal WireGuard/UDP transport used for
node enrollment, configuration delivery and remote CLI profiles (`--profile`).

Internal node RPCs are never exposed over HTTP, and node enrollment/delivery
continues to work even when the HTTP listener is disabled. An integration can
issue a node invitation through REST, but the child always consumes it over
WireGuard UDP.

## OpenAPI contract

`GET /api/v1/openapi.json` returns the [OpenAPI 3.1 document](openapi.json)
embedded in the binary (`application/json`).

Fetching the schema requires `Authorization: Bearer YOUR_TOKEN` on every
transport, including `main`'s local owner-only Unix socket (`state/api.sock`).
Missing, invalid or revoked tokens receive `401`.

`cargo docs` generates [openapi.json](openapi.json) directly from the route
definitions and Rust wire types; `cargo docs --check` verifies it is up to
date.

## Configure the listener

`wgfeel install --control main` enables the HTTP listener on `127.0.0.1:9280`
by default (customizable with `--api-port` and `--api-listen-ip`, or through
the interactive menu). The low-level `wgfeel init --control main` command keeps
HTTP disabled unless `--api-port` is passed.

Inspect or change the port locally on `main` (requires local state-owner
permissions; not callable over REST):

```sh
wgfeel api port
wgfeel api port 8081
```

- **Running service**: binds the new port first, persists the setting, then
  closes the old listener. If binding fails, the existing listener and stored
  settings stay unchanged. WireGuard is never restarted or reconfigured.
- **Stopped service**: verifies the port can be bound and saves it for the next
  start.
- **Uncertain disk commit**: reported as an error; run `wgfeel api port` to
  inspect the active setting before retrying.

Pass `--install-dir PATH` for a custom installation or `--state-dir PATH` for a
manually initialized `main` state directory.

## Authentication and requests

Issue an administrator bearer token locally on `main`:

```sh
wgfeel token rotate
```

This prints the new token once and revokes the previous one. `main` stores only
an HMAC-SHA256 verifier, never the raw token. Send the token in the
`Authorization: Bearer ...` header on every request.

- Loopback requests also require a bearer token; forwarded headers never bypass
  authentication.
- Direct HTTP has no TLS; use the default loopback listener for a local panel
  backend or place a TLS reverse proxy in front for remote access.
- Browser sessions, cookies and CORS are not implemented.

Example HTTP/1.1 request:

```http
GET /api/v1/users HTTP/1.1
Host: localhost:9280
Authorization: Bearer YOUR_TOKEN
Connection: close
```

### Optimistic concurrency and HTTP framing

- Every successful response includes an `ETag` header containing the quoted
  configuration revision (for example `"7"`).
- Configuration changes and token rotation require a matching `If-Match`
  header: missing returns `428`, malformed returns `400`, stale returns `412`.
- `POST /api/v1/node-invitations` does not change the configuration revision.
  `If-Match` is optional; when provided, it is checked at issuance (`400`/`412`)
  without reserving that revision for later enrollment.
- **All `POST` and `PUT` requests**—including empty-body requests such as
  `POST /api/v1/token/rotate` and `POST /api/v1/node-invitations`—must send
  exact `Content-Type: application/json` (`415` otherwise) and `Content-Length`
  (`411` otherwise).
- `POST /api/v1/users/{user}/suspend` and `resume` require the exact two-byte
  body `{}`.
- Requests, headers and connection lifetimes are bounded; rate-limited requests
  receive `429`.

## Endpoints

Full request/response schemas and error codes are in [openapi.json](openapi.json).

| Method & path | Purpose |
| --- | --- |
| `GET /api/v1/openapi.json` | Embedded OpenAPI 3.1 specification |
| `GET /api/v1/identity` | `main`'s node ID and service public key |
| `GET /api/v1/config` | Public desired configuration at the current revision |
| `GET /api/v1/distribution` | Desired and acknowledged revision per node |
| `GET`, `POST /api/v1/users` | List users or create a user and isolated network |
| `GET`, `DELETE /api/v1/users/{user}` | Read or delete a user and its devices |
| `POST /api/v1/users/{user}/suspend`, `resume` | Suspend or resume a user's network (body: `{}`) |
| `GET`, `POST /api/v1/users/{user}/devices` | List or provision devices for a user |
| `GET`, `DELETE /api/v1/users/{user}/devices/{device}` | Read metadata or delete a device |
| `GET /api/v1/users/{user}/devices/{device}/config` | Export WireGuard config (`text/plain`, contains private key; optional `/{network}` suffix) |
| `GET`, `PUT /api/v1/users/{user}/broadcast` | Read or set the default directed broadcast policy |
| `GET`, `PUT /api/v1/users/{user}/devices/{device}/broadcast` | Read or set a device override |
| `GET`, `POST /api/v1/egresses` | List profiles or atomically import a provider profile, placement and initial user assignments |
| `GET`, `PUT`, `DELETE /api/v1/egresses/{egress}` | Read public metadata, replace the provider config or delete the profile |
| `GET`, `PUT /api/v1/egresses/{egress}/node` | Inspect placement, attach, move or unassign a profile |
| `GET`, `PUT /api/v1/users/{user}/egresses` | List or atomically replace a user's assignments |
| `PUT`, `DELETE /api/v1/users/{user}/egresses/{egress}` | Set or remove one assignment |
| `GET`, `POST /api/v1/gateways` | List registered nodes or register one manually |
| `GET`, `DELETE /api/v1/gateways/{gateway}` | Read or remove a registered node |
| `POST /api/v1/node-invitations` | Issue a one-time child enrollment invitation |
| `POST /api/v1/token/rotate` | Rotate the bearer token (available over REST with the current bearer token; the CLI `wgfeel token rotate` is local-only) |

## Directed broadcast

User creation accepts an optional boolean `broadcast` (default `true`). A device
can override it with `true` or `false`. Omit the device setting or pass `null`
to inherit. PUT requires the `broadcast` key and the current `If-Match`.
A repeated stored value preserves the revision. Changing an explicit value to
inherit changes the revision even if the effective policy stays the same.

A device view includes `addresses` (tunnel IP addresses, empty for catalog-only
devices) and `registration` with `broadcast` and `effective_broadcast`.
A catalog-only device has `registration: null` and its broadcast subresource
returns HTTP 409 with `device_unassigned`.

## Save an external WireGuard profile

Send the contents of a single-peer WireGuard profile in the JSON string `config`
to `POST /api/v1/egresses`. The decoded profile can contain up to 16 KiB.
The optional `name` defaults to the peer endpoint host. A successful import
returns `201` with the generated egress ID and the new configuration revision.

Omit `node` to save the profile unassigned on `main`. To grant initial
access in the import transaction, include an eligible `node` and a `users`
array. Each item contains `user`, explicit CIDRs in `routes` and a DNS
selection. These statements use the revision in `If-Match`. If any item
fails validation, the import leaves the prior configuration intact.

`PUT /api/v1/egresses/{egress}/node` takes `{"node":"entry-b"}` to attach
or move a profile and `{"node":null}` to detach it. HTTP 202 means the
former node must acknowledge withdrawal. Inspect the node resource for
`former_node`, `pending_node` and `withdrawal_generation`. Existing assignments
remain dormant during the handoff.

For example, a single-assignment update uses
`{"routes":["10.40.0.0/16"],"dns":{"mode":"zones","zones":["corp.example"]}}`.
DNS also accepts `{"mode":"none"}` and `{"mode":"default"}`. For an
atomic swap of assignments, PUT the collection with an `egresses` array
whose items also include `egress_id`. Use `[]` to remove every assignment.
Provider keys are write-only. Re-export affected devices after changing
their routes or DNS.

## Device configurations

`GET /api/v1/users/{user}/devices/{device}/config` returns the same WireGuard
text as `wgfeel device show`. Treat it as a secret: it contains the device's
private key.

- Each `entry` node serving the user appears as a `[Peer]` section labelled
  with its hostname and ID (or ID alone).
- Alternative addresses are grouped under `# IPv4` and `# IPv6` as commented
  `Endpoint` lines; only the device's assigned home `entry` has `AllowedIPs`
  and `PersistentKeepalive`.
- Set `gateway` when creating a device to choose its home `entry`. The API
  supports this choice only at creation.

## Register or retire a child node

Normal child onboarding uses `POST /api/v1/node-invitations` and `wgfeel join`.
Manual `POST /api/v1/gateways` registration requires distinct base64
`public_key` (service) and `gateway_public_key` (mesh) values. Public read
responses return those fields as `service_public_key` and `gateway_public_key`.

`DELETE /api/v1/gateways/{gateway}` retires the child for all users. Before
retiring an `entry`, check that another `entry` with an advertised endpoint
serves each affected user's network. `main` assigns devices whose home was the
retired node to an eligible replacement. Export a new profile for each of those
devices and import it on the client. If a network has no replacement, profile
export for its affected devices returns `409 gateway_unavailable`.

[README](../README.md) · [Getting started](GETTING_STARTED.md) ·
[Command reference](docs.md) · [Architecture](ARCHITECTURE.md) · [Security policy](SECURITY.md)
