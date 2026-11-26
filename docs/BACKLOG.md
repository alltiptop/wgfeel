# Backlog

Planned work and outstanding acceptance checks.

- [ ] User/device traffic statistics in menus: bytes, handshakes and activity.
- [ ] Carry authenticated control traffic through intermediate children; current
  configuration delivery uses direct main-to-child service sessions. See
  [Architecture](ARCHITECTURE.md#configuration-and-failure-behavior).
- [ ] Change an enrolled node's traffic capability through the administrative API/CLI.
- [ ] CLI changes to installed WG ports, including listeners, service
  settings, installation receipts, endpoint distribution and regenerated client
  configurations requiring reimport.
- [ ] Installation, reboot and removal acceptance on three real hosts with native clients.
- [ ] Load acceptance for 150 networks / 750 devices on 1 GiB RAM.
- [ ] Corporate WireGuard/proxy connectors assigned to an owner Node and user network.
- [ ] API for editing access policies.
- [ ] Quotas and persistent activity statistics.
- [ ] Automated release builds of the common `wgfeel` executable for supported targets.
- [ ] Publish versioned GitHub Releases with binaries, checksums and release notes.

[README](../README.md) · [Contributing](CONTRIBUTING.md)
