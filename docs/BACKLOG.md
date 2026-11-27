# Backlog

- [ ] **User and device activity.** Show bytes sent and received per device and
  totals per user in the administrative menus. Show when each device was last
  seen. Use a documented time window for recent authenticated WireGuard traffic
  or handshakes, and mark a user as recently active if any of their devices
  qualifies. Show unknown status when observations are unavailable.
- [ ] **Reproducible integration and load tests.** Provide a Docker Compose
  setup with main, child nodes and WireGuard clients in separate containers.
  Generate traffic concurrently for several users, verify delivery between each
  user's devices and check isolation between users. Include a repeatable load
  run with 150 networks and 750 configured devices on an entry limited to 1 GiB.
  Document how to run it, how many devices send traffic, and how to compare
  packet delivery, CPU usage and peak memory across runs.
- [ ] **Publish releases.** Publish the Linux x86-64 `wgfeel` binary with a
  checksum and release notes after the version tag passes release CI.
- [x] **External WireGuard gateways per user.** Assign an external WireGuard
  profile to a designated wgfeel node and grant one or more users access to it.
  Their entry nodes forward matching traffic through the mesh to that node,
  which holds the tunnel key and connects to the independently operated gateway.
  Users apply any updated routes in their own client profiles.

  - **Internet exit.** Route the assigned users' internet traffic through the
    external gateway, for example using a compatible WARP or Proton VPN profile.
  - **Selected destinations.** Route traffic for a corporate subnet through a
    standard WireGuard server. Other traffic follows its usual route.

  If a mesh partition cuts off the designated node, the exit is unavailable
  on that side until a route returns. Any future automatic takeover requires
  both an outage and exclusive use of the external profile by the new node.

  - [x] [Test both modes end to end](../crates/wgfeel/tests/support/provider_policy.rs)
    against a local WireGuard peer. The test checks which IPv4 traffic reaches
    the peer, denies access to an unassigned user, and verifies isolation between
    users' devices. Revoking one user's grant preserves another user's UDP flow.

[README](../README.md) · [Contributing](CONTRIBUTING.md)
