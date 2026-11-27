# Security Policy

## Scope and required properties

wgfeel manages isolated user networks through Management, mesh Nodes and standard
WireGuard clients. This policy covers the server and CLI code, installation and
updates, configuration storage, administrative interfaces, DNS and dependencies.

Security-sensitive changes must preserve these properties:

- Traffic is bound to an authenticated user/network and device identity. Source
  validation and ACLs prevent access across users, including overlapping IP ranges.
- Main is the configuration authority. Remote CLI administration requires
  administrative WireGuard access and a bearer token. External HTTP REST
  integrations use a separate TCP listener and require a bearer token, including
  on loopback. Use a TLS reverse proxy for remote HTTP access; the default bind
  is loopback. Local administration uses an owner-only, OS-authenticated Unix socket.
- Main generates 32 random bytes for each administrative bearer token at
  initialization and rotation. Its current private snapshot stores an HMAC-SHA256
  of a random salt keyed by that token. Each authenticated request verifies against
  the current snapshot, including requests following a published rotation.
- Node enrollment and configuration delivery use authenticated service WireGuard
  on the shared UDP port, independently of HTTP REST. External HTTP cannot dispatch
  these internal RPCs; issuing an invitation is an administrative operation, not
  the node's enrollment exchange.
- Each Node receives only its own private keys and the configuration it needs.
  Tokens, invitations, private keys and complete sensitive payloads stay out of logs.
- Service, gateway and per-user client contexts use independent WireGuard keys.
  Gateway membership never grants configuration authority. Relays filter public
  routing metadata; entries authenticate the inner tenant ciphertext and recheck
  device ownership, source addresses and ACLs before delivering plaintext.
- Configuration acceptance requires validation, durable storage and activation.
  Storage failures and uncertain writes must preserve fail-closed behavior.
- Untrusted packets and requests have bounded parsing, queues and resource use.
  Tenant workers remain confined from other tenants and host infrastructure.

Report suspected isolation or authentication bypasses, secret exposure,
unauthorized configuration changes, confinement escapes, unsafe filesystem
operations and denial of service. Include the attacker's required access and the
affected boundary. For dependency reports, include the package version and
advisory ID, with reachable code paths and impact if known.

## Trust boundaries and limitations

Management, the host kernel and shared Node control/dispatch processes are trusted.
An enrolled Node's control process participates in mesh routing; compromising it
can disrupt routing availability. Attacks reaching these components through
untrusted inputs remain security-relevant.

Nodes terminating device tunnels can see decrypted IP traffic. WireGuard protects
individual tunnel hops; use application-layer encryption for end-to-end secrecy.

Management stores device and per-Node key material. Node storage contains its
own keys and accepted configuration. Private directories/files use
`0700`/`0600`; secrets are not encrypted at rest. Protect backups, exported client
profiles and remote administrative profiles accordingly. Join invitations are
temporary credentials and may appear in shell history.

Disconnected Nodes retain their last accepted policy. New revocations and policy
changes take effect when delivered and applied; inspect
`wgfeel config distribution` for acknowledgement status.

The supported server target is Linux x86-64. Real multi-host acceptance and the
published capacity target remain outstanding; see [Backlog](BACKLOG.md).
No long-term support/backport policy or security response SLA is currently defined.

## Reporting a vulnerability

Send your report to the wgfeel maintainers through the
[private vulnerability report form](https://github.com/alltiptop/wgfeel/security/advisories/new).
If the form is unavailable, open a [GitHub issue](https://github.com/alltiptop/wgfeel/issues/new)
asking for a private contact. Share technical details only through the private channel.

Include:

- The affected version or source revision, platform and deployment roles.
- Required access, minimal reproduction steps and expected versus actual behavior.
- The security impact and affected users, keys or services.
- Sanitized logs or a small reproducer using disposable identities and test data.

Keep credentials, live invitations, private keys and deployment data out of public
reports. Coordinate disclosure with the maintainer after a fix and its verification.

[README](../README.md) · [Contributing](CONTRIBUTING.md)
