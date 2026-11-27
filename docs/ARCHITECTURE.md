# Architecture

Every server runs the same `wgfeel` executable and one `wgfeel.service`.
Control authority and user-traffic participation are independent capabilities.

## Node capabilities

One `main` server owns authoritative configuration; all other servers are
`child` nodes. Each host independently participates in user traffic in one of
three modes:

| Traffic mode | Accept device peers | Relay user ciphertext | Carry control traffic |
| --- | --- | --- | --- |
| `entry` | Yes | Yes | Yes |
| `relay` | No | Yes | Yes |
| `off` | No | No | Yes |

All six `main`/`child` × `entry`/`relay`/`off` combinations are supported.
Relays receive public routing policy for their assigned networks, never tenant
private keys. `off` nodes receive neither user-network scope nor tenant keys.
An `entry` `main` can serve devices directly with no separate child host.

## Two separate APIs

- **External HTTP/TCP REST API** on `main` (for web panels and external
  integrations). Installation enables it on `127.0.0.1:9280` by default;
  `wgfeel api port PORT` changes its port locally without affecting WireGuard,
  keys or device profiles. Every request requires a bearer token, including on
  loopback. This listener never dispatches internal node enrollment or
  configuration RPCs. Put it behind a TLS reverse proxy for remote access.
- **Internal WireGuard/UDP transport** (for child enrollment, configuration
  delivery, acknowledgements, mesh routing and remote CLI `--profile` access).
  Authenticated with node, invitation or administrator WireGuard identities.
  Mesh membership never grants REST administration rights.

```text
Panel backend -- HTTP + bearer token --> main
                                           |
                               internal WireGuard mesh
                                           |
                                       children

Phone <-> entry A <-> relay B <-> entry C <-> Laptop
```

## Three cryptographic boundaries on one UDP port

Service, gateway and tenant contexts share a single WireGuard UDP listener per
host, while keeping separate keys and confined worker processes:

| Context | Independent keys | Accepted work |
| --- | --- | --- |
| Service | One permanent service key pair per server; separate temporary invitation and administrator identities | Enrollment, configuration delivery and authenticated administration |
| Gateway | One permanent gateway key pair per server | Mesh health probes, topology announcements and relay envelopes carrying encrypted tenant packets |
| Clients | One tenant key pair per user network on each serving `entry`; each device has its own key | Device WireGuard traffic and encrypted tenant transport between entries |

Service and gateway key pairs are generated independently and persisted
together; key reuse across roles is rejected. A child accepts configuration
only from its pinned `main` service key—being a gateway peer grants no control
or administrator authority.

Each cryptographic context runs in a confined worker process that receives only
its own private key. The dispatcher routes incoming datagrams using WireGuard
authentication and receiver indices; packet type tags cannot cross context
boundaries. No Linux WireGuard interface, TUN device or host forwarding rule is
configured.

```text
service: main ========================================> child
gateway: entry A <============> relay B <============> entry C
clients: phone <==> entry A <------ tenant WG -------> entry C <==> laptop
                            encrypted through relay B
clients: phone <==> entry A <==> laptop
```

`entry` nodes terminate device tunnels and can inspect their users' plaintext.
Between entries, tenant packets stay encrypted across intermediate relays;
relays see only public routing/ACL metadata for their assigned networks. This
protects transit across relays, not device-to-device end-to-end secrecy.

## Policy, routing and failover

- **Uniform policy enforcement**: local forwarding, mesh ingress, relay
  filtering and mesh exit all evaluate the same device-placement and ACL rules.
  Ingress binds each source IP to its authenticated device. Exit authenticates
  the inner tenant peer, derives endpoints from the decrypted packet and
  verifies they match the relay envelope—relay metadata alone never authorizes
  delivery. Cross-network mesh forwarding is rejected (explicit cross-network
  grants remain local to one entry), and user suspension or explicit denies
  apply at every hop.
- **Path selection and recovery**: each node prefers a live direct link to the
  destination `entry`. If that link fails, it selects a shortest path through
  nodes assigned to the user's network. During a partition, nodes keep probing
  peers and resume forwarding as soon as a permitted path returns, even while
  `main` is offline.
- **Loop limits and restarts**: relays decrement the hop limit on every
  forwarded frame and topology announcement (starting at the number of nodes in
  the mesh). Nodes accept increasing announcement sequence numbers from the
  same boot; after an origin restarts, its new boot ID takes over once the
  6-second topology lease expires.

## Configuration delivery and reloads

- **Authoritative revisions**: `main` durably commits each configuration
  revision. Every node receives only its own scope and secrets, persists them
  durably and reports its applied revision. Children keep forwarding their last
  accepted configuration during a `main` outage and catch up once connectivity
  returns. Children do not forward configuration to other children, and there
  are no automatic `main` elections or queued administrative writes.
- **Node withdrawals**: when `main` removes a child, it delivers an
  authenticated withdrawal from its bound UDP port and retains the child's ID
  and public keys until the child acknowledges it (so a permanently offline
  child remains pending). Up to 150 withdrawals can be pending at once.
- **Independent service delivery**: active configuration delivery opens
  main-to-child service sessions over the shared UDP socket independently of
  gateway health or traffic mode, retrying configured endpoints if replies
  stop. Service and gateway contexts drive their own WireGuard handshake and
  rekey timers; rekeying does not reset an active configuration TCP stream.
  Stalled delivery requests release their slot after 5 seconds without
  progress, while progressing transfers keep a separate overall deadline.
- **Revision activation and worker isolation**: policy changes replace mesh
  policy, pending relay work, fragment assemblies and DNS state together.
  Unchanged cryptographic sessions may survive, but old authorization decisions
  never do. `main` keeps a healthy service worker across prepared updates; a
  worker failure alone does not trigger an automatic restart or stop healthy
  tenant workers, and a failed worker can be replaced on the next committed
  revision.

## Endpoint selection and installation layout

Interactive address selection lists local interface addresses—including private
hosting networks and tunnels—while omitting loopback interfaces. The operator
picks reachable addresses in preference order or enters them manually.
Automatic endpoint advertisement enforces the protocol's validation rules,
including rejecting host-specific IPv6 scopes. Traffic mode does not require a
public IP on the host.

Standard installations use `/opt/wgfeel/instance`, one `wgfeel.service` unit
and one `wgfeel` command alias:

- `wgfeel install --control main` defaults to `--traffic entry` (also supports
  `relay` and `off`).
- `wgfeel install --control child` prepares keys and the unit file while
  leaving the service stopped. `main` fixes the child's traffic mode via
  `wgfeel node add --traffic entry|relay|off`; `wgfeel join` receives the
  configuration over WireGuard and starts the service unless installed with
  `--no-start`. An enrolled child's traffic mode is fixed.
- Low-level `wgfeel init` and `wgfeel serve` take the same explicit
  `--control main|child` flag. `update`, `uninstall`, manual page and shell
  completions all operate on that single instance.

## Verification scope

Automated tests cover temporary install/update/uninstall trees, foreground
`main`/`child` processes across all six capability combinations, native-format
client traffic, tenant isolation, authority transfer, failure recovery, and live
or offline HTTP port changes. Generated docs, completions, formatting, Clippy
and the release build are verified separately (see [Contributing](CONTRIBUTING.md)).

These tests do not establish real-host systemd, reboot or production load
acceptance. Planned Docker Compose integration and load tests are tracked in
the [backlog](BACKLOG.md).

## Design references

These public references informed `wgfeel`'s security boundaries and regression
tests (no code from these projects is incorporated; issue links reflect their
authors' reports, not audits of current releases):

- **Cryptokey routing and source binding** —
  [WireGuard cryptokey routing](https://www.wireguard.com/#cryptokey-routing)
  and Tailscale's [security bulletins](https://tailscale.com/security-bulletins)
  (shared-node quarantine) motivate checking context, authenticated peer,
  device ownership and source address together rather than relying on source IP
  alone.
- **Versioned reloads** —
  [Nebula's firewall](https://github.com/slackhq/nebula/blob/master/firewall.go)
  and its [reload issue](https://github.com/slackhq/nebula/issues/1951) inform
  distinguishing committed, active and acknowledged revisions, with tests for
  suspend/resume and recovery after worker failure.
- **Encrypted relaying and failover** —
  [NetBird relay transport](https://docs.netbird.io/help/troubleshooting-relayed-connections)
  and its [unavailable-relay report](https://github.com/netbirdio/netbird/issues/4498)
  motivate keeping relayed payloads encrypted between entries and testing
  authenticated path probes and alternate routes.
- **Packet size and fragmentation** —
  [NetBird PMTU discussion](https://github.com/netbirdio/netbird/discussions/6923)
  motivates testing full 1280-byte inner packets, relay fragmentation and
  IPv4/IPv6 path changes (real-host MTU and file-transfer acceptance remains
  open).

[README](../README.md) · [Getting started](GETTING_STARTED.md) ·
[HTTP REST API](REST_API.md) · [Backlog](BACKLOG.md) · [Contributing](CONTRIBUTING.md)
