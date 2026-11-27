# wgfeel

Private IPv4/IPv6 networks for standard WireGuard clients. Each user gets an
isolated network for their devices, with names such as `laptop.feel.internal`.
Servers run on Linux x86-64.

One `wgfeel` executable supports two independent capabilities:

- **Control**: one `main` owns configuration; all other servers are `child` nodes.
- **Traffic**: `entry` accepts devices, `relay` forwards encrypted mesh traffic,
  and `off` carries control traffic only. Main can use any traffic mode.

Devices of the same user communicate through the mesh:

```text
Phone ⇄ WireGuard ⇄ entry A ⇄ mesh ⇄ relay B ⇄ mesh ⇄ entry C ⇄ WireGuard ⇄ Laptop
```

Children keep forwarding accepted traffic during a `main` outage. Mesh failover
repairs paths between nodes; moving a device off a failed home entry requires
importing an updated client configuration. This is a routed private network,
without broadcast discovery or an Internet exit.

## Build and install

See [Getting started](docs/GETTING_STARTED.md) for prerequisites, firewall rules
and verification steps. Copy the same binary to every server, run installation
as root, and replace the example addresses with reachable endpoints.

```sh
cargo build --release --locked -p wgfeel --bin wgfeel

# Main host
./wgfeel install --control main --traffic entry --endpoint 192.0.2.1:51820 --api-port 9280
# Each child host
./wgfeel install --control child --endpoint 192.0.2.2

# Main: choose the child's traffic mode and issue a one-time invitation
wgfeel node add --traffic entry
# Child: run the printed command and paste the invitation
wgfeel join --invitation-stdin
```

Key deployment details:

- **One service and UDP port**: each server runs `wgfeel.service` with state
  under `/opt/wgfeel/instance` and shares one WireGuard UDP port.
- **Interactive setup**: run `./wgfeel install` without arguments for numbered
  menus, including private and tunnel interface addresses.
- **Child enrollment**: an installed child stays stopped until `wgfeel join`
  receives its configuration over WireGuard UDP on the port assigned by `main`.
- **External REST API**: `main` exposes a separate [HTTP REST API](docs/REST_API.md)
  on `127.0.0.1:9280` by default (change with `wgfeel api port PORT`).
- **Userspace forwarding**: WireGuard keys, mesh routes and ACLs stay inside
  `wgfeel`; no host WireGuard interfaces, TUN devices or kernel forwarding rules
  are configured.

## Common commands

```sh
wgfeel user                       # interactive administration menus on main
wgfeel user add Alice             # creates user and first device, opens user menu
wgfeel device add                 # select a user and add a device
wgfeel device show                # print WireGuard client configuration
wgfeel node list
wgfeel config distribution        # applied configuration revisions per node
./wgfeel.new update --dry-run     # preview an upgrade from a new binary
./wgfeel.new update
wgfeel uninstall --dry-run
wgfeel uninstall                  # keeps state; --purge requires confirmation
```

Import a separate configuration into each device's WireGuard client. An `entry`
`main` can serve devices on its own without any children. Installation also
sets up `man wgfeel` and Bash/Zsh completion, including dynamic user, device
and node IDs on `main`.

## Documentation

- [Getting started](docs/GETTING_STARTED.md) — installation, enrollment, devices, DNS and shell completion
- [Command reference](docs/docs.md) — generated CLI reference for all commands and options
- [HTTP REST API](docs/REST_API.md) — external integration API and OpenAPI contract
- [Architecture](docs/ARCHITECTURE.md) — node roles, cryptographic boundaries, routing and failure handling
- [Security policy](docs/SECURITY.md) — trust boundaries, guarantees and vulnerability reporting
- [Contributing](docs/CONTRIBUTING.md) — development setup, checks, CI and source policy
- [Backlog](docs/BACKLOG.md) — planned features and integration/load testing

## License

Project-owned code and documentation use `AGPL-3.0-only`; see [LICENSE](LICENSE).
Dependencies and adapted [skills](.agents/skills/) retain their separate licenses.
Each skill records upstream authorship, source revision and local changes.
