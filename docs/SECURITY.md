# Security Policy

## Scope and required properties

`wgfeel` manages isolated user networks across a `main` server, `child` mesh
nodes and standard WireGuard clients. This policy covers server and CLI code,
installation and updates, configuration storage, administrative interfaces,
split DNS and dependencies.

Security-sensitive changes must preserve these properties:

- **Per-user isolation**: traffic is bound to an authenticated user/network and
  device identity. Source validation and ACLs block cross-user traffic, even
  when user networks use overlapping IP ranges.
- **Strict administrative boundaries**: `main` is the sole configuration
  authority.
  - Local administration uses an owner-only, OS-authenticated Unix socket
    (`state/api.sock`).
  - Remote CLI administration requires WireGuard authentication plus a bearer
    token.
  - External HTTP REST integrations use a separate TCP listener (loopback by
    default) and always require a bearer token, including on loopback. Use a
    TLS reverse proxy for remote HTTP access.
- **Hashed bearer tokens**: `main` generates 32 random bytes for each
  administrator bearer token on initialization and rotation, storing only an
  HMAC-SHA256 verifier with a random salt in its private state. Every
  authenticated request is verified against the current snapshot.
- **Isolated node control**: child enrollment and configuration delivery run
  over authenticated service WireGuard on the shared UDP port, independently of
  HTTP REST. External HTTP cannot dispatch internal node RPCs (issuing an
  invitation only creates a temporary credential; enrollment itself always uses
  WireGuard).
- **Least privilege and clean logs**: each node receives only its own private
  keys and assigned configuration. Tokens, invitations, private keys and raw
  sensitive payloads must stay out of logs.
- **Key separation and relay defense**: service, gateway and per-user client
  contexts use independent WireGuard key pairs. Gateway membership never grants
  configuration authority. Relays filter on public routing metadata; `entry`
  nodes authenticate the inner tenant ciphertext and recheck device ownership,
  source addresses and ACLs before delivering plaintext.
- **Fail-closed durability**: configuration acceptance requires validation,
  durable storage and activation. Storage failures or uncertain writes must
  fail closed.
- **Bounded work and confinement**: untrusted packets and HTTP requests have
  bounded parsing, queues and resource limits. Tenant workers run confined from
  other tenants and host infrastructure.

Report suspected isolation or authentication bypasses, secret leaks,
unauthorized configuration changes, confinement escapes, unsafe filesystem
operations or denial-of-service bugs. Include the attacker's required access
and affected boundary (for dependency advisories, include package version,
advisory ID and reachable code paths if known).

## Trust boundaries and limitations

- `main`, the host kernel and each node's shared control/dispatch process are
  trusted. Compromising an enrolled node's control process can disrupt mesh
  routing availability; attacks reaching these components via untrusted input
  remain security-relevant.
- `entry` nodes terminate device tunnels and can see decrypted IP traffic.
  WireGuard protects each tunnel hop; use application-layer encryption (such as
  TLS or SSH) for end-to-end secrecy.
- Each server generates and keeps its own permanent service and gateway private
  keys. Recovering a child's identity requires that child's backup. `main`
  also stores the device private keys it generates and the private key for
  each user network on each serving `entry`.
- Secrets are stored unencrypted on disk. Private directories use mode `0700`
  and secret files use `0600`. Protect backups, exported client configs and
  remote admin profiles. Use `--invitation-stdin` to keep join invitations
  out of command arguments and shell history.
- A disconnected child keeps enforcing its last applied policy. A revocation
  takes effect on that child as soon as it applies the new revision.
  `wgfeel config distribution` shows `pending` until `main` receives confirmation,
  even if the child is already enforcing the change.
- Only Linux x86-64 servers are supported. Real multi-host deployment and
  production load testing are not yet verified (see the [backlog](BACKLOG.md)).
  No long-term support, backport policy or response SLA is currently defined.

## Reporting a vulnerability

Report vulnerabilities privately using the
[GitHub private vulnerability report form](https://github.com/alltiptop/wgfeel/security/advisories/new).
If the form is unavailable, open a [GitHub issue](https://github.com/alltiptop/wgfeel/issues/new)
requesting a private contact—do not post technical exploit details publicly.

Please include:

- Affected version or commit, platform and node roles (`main`/`child`,
  `entry`/`relay`/`off`).
- Required access, minimal reproduction steps, and expected vs. actual behavior.
- Security impact and affected users, keys or services.
- Sanitized logs or a small reproducer using disposable identities and test data.

Keep credentials, live invitations, private keys and real deployment data out
of public reports. Coordinate disclosure with the maintainer after a fix is
verified.

[README](../README.md) · [Getting started](GETTING_STARTED.md) · [Contributing](CONTRIBUTING.md)
