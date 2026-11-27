# wgfeel

Private IPv4/IPv6 networks for standard WireGuard clients. Each user has an
isolated network for their devices, with names such as `laptop.feel.internal`.
Servers run on Linux x86-64.

One `wgfeel` executable supports two independent capabilities:

- Control: one `main` owns configuration; other instances are `child` nodes.
- Traffic: `entry` accepts devices, `relay` forwards encrypted mesh traffic,
  and `off` carries only control traffic. Main can use any of these modes.

Devices of the same user communicate through the mesh:

```text
Phone ⇄ WireGuard ⇄ entry A ⇄ mesh ⇄ relay B ⇄ mesh ⇄ entry C ⇄ WireGuard ⇄ Laptop
```

Children keep forwarding accepted traffic during a main outage. Mesh failover
repairs paths between nodes; replacing a device's home entry requires importing
an updated client configuration. This is a routed private network, without
broadcast discovery or an Internet exit.

## Build and install

See [Getting started](docs/GETTING_STARTED.md) for prerequisites and checks.
Copy the same binary to every server; run installation as root and replace the
example addresses with reachable endpoints.

```sh
cargo build --release --locked -p wgfeel --bin wgfeel

# Main host
./wgfeel install --control main --traffic entry --endpoint 192.0.2.1:51820 --api-port 9280
# Each child host
./wgfeel install --control child --endpoint 192.0.2.2

# Main: choose the child's traffic mode and issue a one-time invitation
wgfeel node add --traffic entry
# Child: run the printed command
wgfeel join --invitation-stdin
```

Each instance uses one WireGuard UDP listener and `wgfeel.service`; its state is
under `/opt/wgfeel/instance`. Main also has a separate [HTTP REST API](docs/REST_API.md),
defaulting to `127.0.0.1:9280`. Change its port with `wgfeel api port PORT`.
Run `./wgfeel install` for numbered menus and select one or more reachable
addresses, including private or tunnel addresses. A child stays stopped until
`wgfeel join` receives its configuration on the UDP port assigned by main.
Both peers send and receive enrollment traffic on their mesh UDP port. WireGuard
keys, mesh routes and client ACLs live in wgfeel. The host supplies UDP transport
through its existing interfaces.

## Commands

```sh
wgfeel user                      # interactive administration on main
wgfeel user add Alice            # also asks for the first device
wgfeel device add                # select a user and name a device
wgfeel device show               # WireGuard client configuration
wgfeel node list
wgfeel config distribution       # applied configuration revisions
./wgfeel.new update --dry-run     # preview an update from the new binary
./wgfeel.new update
wgfeel uninstall --dry-run
wgfeel uninstall                 # retains state; --purge requires confirmation
```

Import a separate configuration into each device's WireGuard client. An entry
main can serve devices without a child. Installation includes `man wgfeel` and
Bash/Zsh completion, including existing user/device/node IDs on main.
See the [command reference](docs/docs.md) and [shell setup](docs/CONTRIBUTING.md#manuals-and-shell-completion).

## Development

[Contributing: commands and verification](docs/CONTRIBUTING.md) ·
[Architecture](docs/ARCHITECTURE.md) · [Backlog](docs/BACKLOG.md)

## License

Project-owned code and documentation use `AGPL-3.0-only`; see [LICENSE](LICENSE).
Dependencies and adapted [skills](.agents/skills/) retain their separate licenses.
Each skill records upstream authorship, source revision and local changes.

[Security policy](docs/SECURITY.md)
