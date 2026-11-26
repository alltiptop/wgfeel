# Unified node model

All installations use one `wgfeel` executable and one service. Control authority
and user-traffic participation are independent capabilities.

## Independent capabilities

Every host runs the same `wgfeel` binary and one service. One configured `main`
owns authoritative configuration. All other participants are `child` nodes.
Control authority is independent of the user-traffic mode:

| Traffic mode | Accept device peers | Relay user ciphertext | Carry control traffic |
| --- | --- | --- | --- |
| `entry` | Yes | Yes | Yes |
| `relay` | No | Yes | Yes |
| `off` | No | No | Yes |

All six combinations are supported. Relays receive public
routing policy for their assigned networks, but no tenant private keys. Off nodes
receive neither user-network scope nor tenant keys. A main can serve devices
without installing a second binary or running a second public UDP listener.

## Two distinct APIs

- The external REST API runs on a separate **HTTP/TCP** listener on main. It is
  intended for web-panel backends and other integrations. Installation asks for
  its port; an explicit local command can change that port after installation.
  Network requests always require an administrator token, including loopback
  requests. This listener cannot dispatch internal enrollment/configuration RPCs.
- Node enrollment, configuration delivery, acknowledgements and mesh control use
  the internal **WireGuard/UDP** transport. They are authenticated with node or
  invitation identities. Mesh membership grants no REST administration rights.

The single-port requirement concerns WireGuard: service, gateway and tenant contexts share
one UDP listener per host. The external HTTP listener is independent, and changing
its port must not change the mesh port, keys or device configurations. HTTP binds
to loopback by default; deployment behind a TLS reverse proxy supports remote
integrations without adding a TLS implementation to wgfeel.

## Three cryptographic boundaries, one UDP listener

| Context | Independent keys | Accepted work |
| --- | --- | --- |
| Service | One permanent service key pair per instance; separate temporary invitation and administrator identities | Enrollment, configuration and authenticated administration |
| Gateway | One permanent gateway key pair per instance | Mesh health, routing and relay envelopes carrying encrypted tenant packets |
| Clients | One tenant key pair per user network on each serving entry; each device has its own key | Device traffic and encrypted tenant transport between entries |

Service and gateway identities are generated independently and persisted together.
Assignments and enrollment include both public keys. Key reuse across roles is
rejected. A child accepts configuration only from its pinned main service identity;
being a gateway peer grants no configuration or administrator authority.

One application service owns the UDP socket. Each cryptographic context runs in a
confined worker process receiving only its own private key. The dispatcher uses
WireGuard authentication and receiver indices to select a context. Packet type
tags cannot switch its authority. No Linux WireGuard interface, TUN device or host
forwarding rule is installed.

```text
service: main ========================================> child
gateway: entry A <============> relay B <============> entry C
clients: phone <==> entry A <------ tenant WG -------> entry C <==> laptop
                            encrypted through relay B
clients: phone <==> entry A <==> laptop
```

Entries terminate native device tunnels and can inspect their users' plaintext.
Between entries, a tenant packet stays encrypted through intermediate relays.
Relays receive only public routing/ACL metadata for their assigned networks and
their own gateway keys. This does not provide device-to-device end-to-end secrecy.

Local forwarding, mesh ingress, relay filtering and mesh exit call the same
`GatewayProjection::forwarding_decision` contract for ACLs and device placement.
Ingress binds the source IP to its authenticated device. Exit authenticates the
inner tenant peer, derives endpoints from the decrypted packet and checks that
they match the relay envelope. Relay metadata alone never authorizes delivery.
Explicit cross-network grants remain local to one entry; cross-network mesh
forwarding is rejected. Same-user mesh traffic follows the same policy at each
hop, including suspension and explicit denies.

A relay decreases the hop limit of every forwarded data frame and topology
announcement. The initial limit is the number of nodes in the mesh. A node
accepts increasing announcement sequences from the same boot. When an origin
restarts, its new boot ID can take over after the six-second topology lease expires.

## Configuration and failure behavior

Main durably publishes each configuration revision. Each participant receives
only its own configuration and secret material, applies it durably, and reports
the applied revision. Forwarding retains the last accepted configuration during a
main outage. A disconnected node catches up when a path becomes available.

When main removes a child, it delivers the withdrawal from the same bound UDP
port. Main retains the child's ID and public keys until it receives the child's
authenticated acknowledgement. A permanently offline child therefore remains
pending. Up to 150 withdrawals can be pending at once.

Active configuration delivery establishes its own main-to-child service sessions
on the common UDP socket, independently of gateway health or traffic mode. It
retries configured addresses when service replies stop. Service and gateway
contexts each drive their own WireGuard handshake and rekey timers. Rekeying does
not reset an active configuration TCP stream. Abandoned distribution requests
release their slot after five seconds without progress; progressing requests
retain the separate overall request deadline.

Delivery through intermediate children remains planned: end-to-end
authentication must still identify main and the intended recipient, without
granting a forwarding child authority. User traffic remains separated by tenant
context and policy. There are no automatic main elections or queued
administrative writes in the MVP.

The active revision is the application baseline. Policy changes replace mesh
policy, pending relay work, fragment assemblies and DNS decisions together.
Unchanged cryptographic sessions may survive, but old permission decisions do
not. Main retains a healthy service worker during prepared configuration changes;
a failed worker can be replaced by a newly committed revision. A worker failure
alone does not cause an automatic restart or stop healthy tenant workers.

```text
Panel backend -- HTTP + token --> main
                                  |
                    internal WireGuard mesh
                                  |
                               children

Phone <-> entry A <-> relay B <-> entry C <-> Laptop
```

Address selection lists local interface addresses, including private hosting
networks and tunnels. Loopback interfaces are omitted. The operator selects reachable addresses
in preference order or enters them manually. Automatic advertisement retains the protocol's endpoint validation,
including its restriction on host-specific IPv6 scopes. Traffic mode does not
determine whether the host physically has a public address.

## Installation and command interface

The layout is `/opt/wgfeel/instance`, with one `wgfeel.service` and command alias.
`wgfeel install --control main|child` selects control authority. Main defaults to
`--traffic entry`; it also supports `relay` and `off`. Main selects child traffic
policy with `wgfeel node add --traffic entry|relay|off`, which prints the advertised main endpoints, the assigned child UDP port and
a one-time `wgfeel join` command. An installed unbound child has no running
service. The join process receives the configuration over WireGuard and activates
the installed service after the binding has been committed. Changing an enrolled child's mode remains planned.

`wgfeel init` and `wgfeel serve` use the same explicit `--control main|child`
selection. Update, uninstall, manuals and completion operate on that one instance.

Remote CLI profiles use WireGuard authentication and an administrative bearer
token on main's shared UDP listener. Enrollment verification and withdrawal of
retired children also use authenticated WireGuard exchanges. The external HTTP
listener requires a bearer token and rejects internal node RPCs and local
owner-only operations.

## Verification scope

Local tests exercise temporary installation/update/removal trees, foreground
main/child processes in all six capability combinations, native-format client
traffic, isolation, authority transfer and failure recovery, and live/offline
HTTP port changes. Generated documentation, completion, formatting, Clippy and
the common release build are checked separately; see [Contributing](CONTRIBUTING.md).
These checks do not establish real-host systemd, reboot or load acceptance.
Outstanding deployment acceptance and multi-hop control delivery are tracked in
[Backlog](BACKLOG.md).

## Lessons from other implementations

These references inform the boundaries and regression scenarios; their code is
not incorporated into wgfeel:

- [WireGuard cryptokey routing](https://www.wireguard.com/#cryptokey-routing)
  binds inner source addresses to authenticated peer keys. Tailscale's
  [shared-node quarantine bulletin](https://tailscale.com/security-bulletins)
  also demonstrates why source-IP-only filtering is insufficient. wgfeel checks
  context, authenticated peer, device ownership and source address together.
- [Nebula's firewall](https://github.com/slackhq/nebula/blob/master/firewall.go)
  versions connection tracking against rule changes. Its
  [configuration reload report](https://github.com/slackhq/nebula/issues/1951)
  describes comparing against a previous desired configuration after partial
  failure. wgfeel distinguishes committed, active and acknowledged revisions;
  regressions cover suspend/resume and replacement after worker failure.
- [NetBird relay transport](https://docs.netbird.io/help/troubleshooting-relayed-connections)
  keeps relayed payloads encrypted. wgfeel applies that property between entries
  while retaining native device clients. The
  [unavailable-relay report](https://github.com/netbirdio/netbird/issues/4498)
  motivates authenticated path probes and alternate-path tests.
- The [NetBird PMTU report](https://github.com/netbirdio/netbird/discussions/6923)
  describes large requests stalling while smaller ones work. wgfeel tests full
  1280-byte inner packets, relay fragmentation and IPv4/IPv6 path changes.
  This is not proof that arbitrary underlying path MTUs work: real-host MTU and
  file-transfer acceptance remains outstanding.

The issue/discussion links are reports by their authors, not independent audits
of those projects or claims about every current release.

[README](../README.md) · [Backlog](BACKLOG.md) · [Contributing](CONTRIBUTING.md)
