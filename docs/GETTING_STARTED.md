# Getting started

This guide installs one main and two child entries, then connects two devices
belonging to one user. An entry main alone is enough to try device networking;
children exercise the mesh.

```text
Phone ⇄ WireGuard ⇄ Node A ⇄ encrypted mesh ⇄ Node B ⇄ WireGuard ⇄ Laptop
                         ↑ configuration from Management ↑
```

## Prepare hosts and binaries

Use Linux x86-64 hosts with glibc, systemd, `/proc` and seccomp support. Install
and administer each instance as root. Local administrative sockets and state are
owner-only; running the installed CLI as an unrelated user will fail. Main can also serve devices through its own UDP listener.

On a development machine, follow [environment setup](CONTRIBUTING.md#prepare-a-development-machine),
then build from the workspace root:

```sh
cargo build --release --offline --locked -p wgfeel --bin wgfeel
```

Copy the same `target/release/wgfeel` executable to every host using your normal
secure transfer method. Copying the binaries is sufficient; installation generates manuals and
completion resources. The GNU/Linux build uses system glibc and `libgcc_s`:
build on the target distribution or one with a compatible, no-newer glibc.

Choose reachable unicast endpoint addresses. The `192.0.2.x` addresses below are
examples and must be replaced. For IPv6, use `[address]:port`. Configure the host
and provider firewalls before enrollment:

| Destination | UDP port in this guide | Required sources |
| --- | --- | --- |
| Main or child | `51820` | Other participating nodes; native WireGuard clients if traffic mode is entry. |

Allow the corresponding outbound traffic and return packets. If a host is behind
NAT, forward its advertised UDP endpoint to its listener and keep that mapping
stable. The installer does not configure firewalls or NAT. The independent REST
API for integrations defaults to `127.0.0.1:9280`; no public TCP opening is needed
for a local backend. Use a TLS reverse proxy for remote integrations. Servers forward in userspace; host IP forwarding,
TUN interfaces and a kernel WireGuard module are not required for this setup.

## Install and enroll

On Management, as root:

```sh
./wgfeel install --control main --traffic entry --endpoint 192.0.2.1:51820 --dry-run
./wgfeel install --control main --traffic entry --endpoint 192.0.2.1:51820
systemctl status wgfeel.service --no-pager
```

Run `./wgfeel install` for numbered menus. On main, choose the traffic mode,
the external HTTP port (9280 by default), then the WireGuard UDP port (51820).
At the address prompt enter one or more numbers, for example `2,1` for IPv6
and IPv4. The first address is the preferred contact. You can also enter a
reachable NAT mapping. Private networks and tunnels are eligible for selection.
Loopback addresses are hidden from the list. For scripted installs repeat
`--endpoint` in the same order.

Choose a unique node name for the mesh. It becomes the persistent node ID.
The default is `main` on main and the short hostname on child. Use `--id`
to override it, for example on hosts cloned from the same image.

On Node A, as root:

```sh
./wgfeel install --control child --endpoint 192.0.2.2
```

Repeat on Node B with its own IP, for example `192.0.2.3`. The child installer
prepares keys and the unit file. The service stays stopped until enrollment.

On Management, generate a fresh invitation for Node A:

```sh
wgfeel node add --traffic entry
```

Run the printed `wgfeel join --invitation-stdin` command as root on Node A, then paste the invitation at its prompt.
The output of `node add` lists the main endpoints and the child's assigned UDP
port. Allow that port on the child. The join command binds it during enrollment,
saves the verified configuration, then enables and starts `wgfeel.service`.
An installation staged with `--no-start` stays stopped after join. Generate a separate invitation and repeat on
Node B. Invitations are temporary, single-use credentials; keep them out of
public logs, screenshots and shell history shared with others.

Use `--traffic relay` for a child that only relays encrypted user traffic, or
`--traffic off` for control only. Main chooses this policy when issuing the
invitation; the child cannot change it through its join request.

On Management, verify both registrations and configuration delivery:

```sh
wgfeel node list
wgfeel config distribution
```

Inspect delivery again after each configuration change; registration alone does
not prove a Node has applied the new policy.

## Connect devices

Install a standard WireGuard client on each device. On Management, as root:

```sh
wgfeel user add Alice
```

Name the first device `Phone` when prompted. Its details show a WireGuard
configuration; import it privately into the phone's client. Leave the menu, then:

```sh
wgfeel device add
```

Select Alice and name the second device `Laptop`. Import its separate configuration
into the laptop's client and activate both tunnels. Management generates keys,
addresses and device hostnames, and selects a home Node automatically. In the
export, each entry Node has a `[Peer]` section labelled with `# Node:`. The home
Node is the peer with `AllowedIPs` and carries the device's traffic. Each peer's
advertised endpoints are grouped under `# IPv4` and `# IPv6`. To switch addresses
on the same Node, comment out its current `Endpoint` line and uncomment the
desired one. Never reuse one device's configuration for another device.

Use `wgfeel device show` to reopen details. Record each device's `Address` and
the `# available at …` hostname from its exported configuration. From one device,
ping the other device's assigned IPv4 and IPv6 addresses, then its displayed
`*.feel.internal` hostname. Allow ICMP or a chosen test service in the receiving
device's own firewall. Configure split DNS on the client: route the domain
`feel.internal` to the address in the exported `# Split DNS` comment. Keep
the device's usual resolver for all other names. The portable WireGuard
profile leaves system DNS selection to the client. Devices without domain-based
DNS routing can reach their peers by the IP addresses in their profiles.

On Linux with systemd-resolved, run these commands after bringing up the
tunnel. Substitute the interface name and DNS address from the profile.

```sh
resolvectl dns <interface> <wgfeel-dns-address>
resolvectl domain <interface> '~feel.internal'
resolvectl default-route <interface> no
```

Use `resolvectl query <device>.feel.internal` and `resolvectl query example.org`
to check which link answers each query. Use `resolvectl revert <interface>` when
removing these settings from an interface that remains present.

Only the private network prefixes go through these tunnels; this setup does not
provide an Internet exit. Users have isolated address spaces: devices belonging
to different users cannot communicate through wgfeel. Nodes keep their accepted
configuration during a Management outage; new changes and revocations need
delivery. Mesh path recovery does not move a device off a failed home Node;
changing that Node requires reimporting the updated client configuration.

## Diagnose a connection

On the affected server, as root:

```sh
# Management host
journalctl -u wgfeel.service -n 100 --no-pager
wgfeel node list
wgfeel config distribution

# Node host
journalctl -u wgfeel.service -n 100 --no-pager
wgfeel state-check --state-dir /opt/wgfeel/instance/state
```

If enrollment fails, check service state, endpoint addresses, UDP reachability
and invitation expiry. If traffic fails, inspect the client's handshake status,
configuration delivery and device firewall. If IP works but names fail, inspect
the client's DNS configuration. For permission errors, use the installation
owner and inspect path ownership; do not make state or credentials world-readable.
Sanitize logs before sharing them, and never attach exported private configurations.

## Preserve state and remove an installation

Each instance keeps its identity, keys, configuration and installation receipt
under `/opt/wgfeel/instance`. Main also keeps authoritative state and its local
administrative profile there. A custom `--install-dir` replaces the `/opt/wgfeel` base.

For a consistent backup, stop `wgfeel.service` during a maintenance window,
back up its complete directory with ownership and permissions preserved, then
start the service again. Include its installed systemd unit and note the binary
version and endpoints. Store backups encrypted and outside the source tree.
Private state/configuration directories use `0700` and secret files `0600`.

Restore with the service stopped, the same binary version, paths and endpoints,
preserving the complete instance directory and service unit. Reload systemd after
restoring a unit, then start the service and verify delivery and client traffic.
Do not run `install` over restored state or start two hosts with the same restored
Node identity. Restoring old Management state can undo revocations: reconcile
users/devices and rotate affected credentials before resuming normal use. Nodes
can reject restored configuration older than their accepted generation; verify
delivery before treating recovery as complete.

To remove an instance, run `wgfeel uninstall --dry-run`, review it, then repeat
without `--dry-run`.
State is retained by default. `--purge` removes it after confirmation.

[README](../README.md) · [Command reference](docs.md) ·
[Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)
