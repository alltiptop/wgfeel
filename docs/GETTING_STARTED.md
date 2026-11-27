# Getting started

This guide installs one `main` server and two `child` entries, then connects
two devices belonging to one user. An `entry` `main` alone is enough to try
device networking; adding children exercises the mesh.

```text
Phone ⇄ WireGuard ⇄ child A (entry) ⇄ encrypted mesh ⇄ child B (entry) ⇄ WireGuard ⇄ Laptop
                                 ↑ configuration from main ↑
```

## Prepare hosts and binary

Use Linux x86-64 hosts with glibc, systemd, `/proc` and seccomp support. Install
and administer each instance as root: the local Unix socket and state files are
owner-only, so running the installed CLI as another user fails.

On a development machine, complete [environment setup](CONTRIBUTING.md#prepare-a-development-machine),
then build from the workspace root:

```sh
cargo build --release --locked -p wgfeel --bin wgfeel
```

Copy `target/release/wgfeel` to every server over a secure channel. The binary
alone is enough: installation generates the manual page and shell completions
automatically. Build on the target Linux distribution or one with an older or
matching glibc version.

Choose reachable unicast endpoint addresses. Replace the documentation-only
`192.0.2.x` addresses below with your own (for IPv6, use `[address]:port`).
Open UDP traffic in your host and provider firewalls before enrolling children:

| Destination | Default UDP port | Required sources |
| --- | --- | --- |
| `main` or `child` | `51820` | Other mesh nodes, plus WireGuard clients when traffic mode is `entry`. |

Allow outbound UDP and return packets. Behind NAT, forward the advertised UDP
port to the listener and keep the mapping stable (the installer does not touch
firewalls or NAT).

`main`'s external [HTTP REST API](REST_API.md) binds to `127.0.0.1:9280` by
default, so no public TCP port is needed for local integrations. Put it behind
a TLS reverse proxy for remote access. Because `wgfeel` forwards in userspace,
hosts do not need IP forwarding, TUN devices or the kernel WireGuard module.

## Install and enroll

### 1. Install `main`

On the `main` host, as root:

```sh
./wgfeel install --control main --traffic entry --endpoint 192.0.2.1:51820 --dry-run
./wgfeel install --control main --traffic entry --endpoint 192.0.2.1:51820
systemctl status wgfeel.service --no-pager
```

To use interactive menus instead of flags, run `./wgfeel install` with no
arguments. For `main`, the installer asks for:

1. Control capability (`main` or `child`).
2. Traffic mode (`entry`, `relay` or `off`).
3. External REST HTTP port (`9280` by default).
4. WireGuard / mesh UDP port (`51820` by default).
5. Advertised endpoints — select one or more detected interface addresses by
   number (for example `2,1` to prefer IPv6 over IPv4) or enter a reachable NAT
   address. Private and tunnel interfaces are included; loopback is omitted.
6. Unique node name (defaults to `main` on `main`, or the short hostname on
   `child`; override with `--id`, for example on cloned VMs).

For scripted installs with multiple endpoints, repeat `--endpoint` in preference
order.

### 2. Install `child` hosts

On child A, as root:

```sh
./wgfeel install --control child --endpoint 192.0.2.2
```

Repeat on child B with its own IP (for example `192.0.2.3`). Child installation
creates keys and `wgfeel.service`, and leaves the service stopped until join.

### 3. Enroll children into the mesh

On `main`, issue a one-time invitation for child A:

```sh
wgfeel node add --traffic entry
```

The output prints `main`'s endpoints, the child's assigned UDP port, and the
join command. Make sure that UDP port is allowed on child A, then run the
printed command as root on child A and paste the invitation when prompted:

```sh
wgfeel join --invitation-stdin
```

`wgfeel join` binds the assigned UDP port, completes enrollment over WireGuard,
saves the verified configuration, and enables and starts `wgfeel.service`
(unless installed with `--no-start`). Issue a separate invitation and repeat
for child B.

- Use `--traffic relay` for a child that only relays encrypted mesh traffic, or
  `--traffic off` for control traffic only. `main` fixes this mode in the
  invitation; a child cannot change it.
- Invitations are single-use credentials valid for 15 minutes. Keep them out of
  logs, screenshots and shared shell history.

Verify both nodes on `main`:

```sh
wgfeel node list
wgfeel config distribution
```

Check `wgfeel config distribution` after every configuration change: listing a
node only confirms registration, not that it has applied the latest revision.

## Connect devices

Install a standard WireGuard client on each device. On `main`, as root:

```sh
wgfeel user add Alice
```

1. Name the first device `Phone` when prompted. `user add` then opens Alice's
   menu (`1. add device`, `2. remove user`, `3. suspend user`, `4. show devices`).
2. Select `4` (`show devices`), then `1` (`Phone`) to display its WireGuard
   configuration. Import it privately into the phone's WireGuard client.
3. Add a second device named `Laptop`—either by choosing `1` (`add device`) in
   Alice's menu or by exiting and running `wgfeel device add`. Import its
   separate configuration into the laptop's client and activate both tunnels.

Never reuse one device's configuration on another device. Use
`wgfeel device show` at any time to reopen a device's details and configuration.

### Export format and endpoints

`main` generates keys, IPv4/IPv6 addresses and hostnames automatically, and
assigns each device a home `entry` node.

- Each `entry` node serving the user appears as a `[Peer]` section labelled
  with `# Node:`.
- Only the device's home `entry` has `AllowedIPs` and `PersistentKeepalive`.
- Alternative endpoints on each node are grouped under `# IPv4` and `# IPv6`
  as commented `Endpoint` lines. To switch addresses on the same node, comment
  out the active `Endpoint` line and uncomment another.

### Test connectivity and split DNS

From each exported configuration, note the device's `Address` and its
`# available at <name>.feel.internal` hostname.

1. Ping the other device's IPv4 and IPv6 addresses (allow ICMP or your test
   service in the receiving device's firewall).
2. Configure split DNS on the client so only `feel.internal` goes to the
   address in the `# Split DNS` comment, keeping your normal resolver for all
   other domains. Devices without split DNS can always connect by IP.

On Linux with `systemd-resolved`, run after bringing up the tunnel (replace
`<interface>` and `<wgfeel-dns-address>`):

```sh
resolvectl dns <interface> <wgfeel-dns-address>
resolvectl domain <interface> '~feel.internal'
resolvectl default-route <interface> no
```

Verify with `resolvectl query <device>.feel.internal` and
`resolvectl query example.org`. Use `resolvectl revert <interface>` to clear
the settings if the interface stays up.

Only private user prefixes route through the tunnel (no Internet exit), and
different users are isolated from one another. Children keep their last applied
configuration during a `main` outage. Mesh failover repairs paths between
nodes, but does not move a device off a failed home `entry`—changing a
device's home `entry` requires importing an updated client configuration.

## Manual and shell completion

Installation writes the manual page and completion adapters as mode-`0644`
files:

| Resource | Installed path |
| --- | --- |
| Manual page | `/usr/local/share/man/man1/wgfeel.1` |
| Bash completion | `/usr/local/share/bash-completion/completions/wgfeel` |
| Zsh completion | `/usr/local/share/zsh/site-functions/_wgfeel` |

Read the manual with `man wgfeel`. Bash loads completions through
`bash-completion`; Zsh loads them from `fpath` after `compinit`. To enable
completion immediately in an existing shell (or add it to your shell rc file):

```bash
source <(wgfeel completions bash)
```

```zsh
autoload -Uz compinit
compinit
source <(wgfeel completions zsh)
```

Tab completes commands, flags, fixed values and file paths. On `main`, it also
suggests existing user, device and node IDs (for example `device add --user`),
using read-only requests with a 500 ms local timeout (3 s for remote
`--profile` access). If `main` is unreachable or access is denied, dynamic
suggestions stay empty and static completion continues to work.

`wgfeel update` refreshes these files automatically; `wgfeel uninstall` removes
only unmodified receipt-owned files.

## Diagnose a connection

On the affected server, as root:

```sh
# On main
journalctl -u wgfeel.service -n 100 --no-pager
wgfeel node list
wgfeel config distribution

# On a child
journalctl -u wgfeel.service -n 100 --no-pager
wgfeel state-check --state-dir /opt/wgfeel/instance/state
```

Quick checklist:

- **Enrollment fails**: check `wgfeel.service`, advertised endpoints, UDP
  reachability on both sides, and the 15-minute invitation expiry.
- **Traffic fails**: check the WireGuard client handshake, `wgfeel config distribution`,
  and the receiving device's firewall.
- **IP works, names fail**: check client split-DNS settings for `feel.internal`.
- **Permission errors**: run as the installation owner (`root`) and verify
  directory ownership; never make state or credential files world-readable.

Sanitize logs before sharing them, and never attach exported client
configurations.

## Backup, restore and uninstall

### Back up each server

Back up `main` and each `child` separately so you can recover each server's
identity. On `main`, the instance directory also holds the authoritative
configuration in `state/` and the remote administrator WireGuard profile in
`config/admin.json`. That profile contains a private key even before you add
an API token.

Record the binary version, endpoints and whether `wgfeel.service` is enabled
at boot (`systemctl is-enabled wgfeel.service`). Stop the service and archive
these paths, preserving ownership, permissions and symlinks:

- The entire `/opt/wgfeel/instance/` directory, or `<install-dir>/instance/`
  for a custom installation.
- The unit file `/etc/systemd/system/wgfeel.service`.
- The command symlink `/usr/local/bin/wgfeel`.
- The [manual page and both shell completion files](#manual-and-shell-completion).

Store the archive encrypted outside the repository. Start the service again
if it was running before the backup.

### Restore a server

1. Stop the service and keep the original host offline if you are replacing
   it. Restore all archived paths to their original locations, with the same
   ownership, permissions and symlink targets. Keep the same endpoints. The
   archive includes the installed binary, so skip `wgfeel install`. Run
   `systemctl daemon-reload`.
2. On a restored `main`, block access to its HTTP API (including through any
   reverse proxy) and block WireGuard traffic in both directions before startup.
   Start `wgfeel.service`. Use the local CLI to reapply user, device and node
   revocations made since the backup. If the administrator token changed since
   then, run `wgfeel token rotate` and update integrations. Once the access
   settings are current, reopen the network connections.
3. On a restored `child`, start `wgfeel.service` if it was previously running.
   On either role, run `systemctl enable wgfeel.service` if the service was
   enabled at boot before the backup.
4. On `main`, check `wgfeel config distribution` and verify device traffic.
   A child that already applied a newer revision will reject an older one.

### Uninstall

Preview removal with `wgfeel uninstall --dry-run`, then run `wgfeel uninstall`.
The default keeps state and keys. To delete them as well, add `--purge` and,
in noninteractive mode, `--confirm wgfeel`.

[README](../README.md) · [Command reference](docs.md) ·
[HTTP REST API](REST_API.md) · [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)
