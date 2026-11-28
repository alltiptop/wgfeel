# Contributing

Keep changes focused and preserve existing behavior outside your scope. For
security-sensitive work, follow the [security policy](SECURITY.md).

## Development rules

- Use English for all project text, including commit messages, code comments,
  documentation, and user-facing messages.
- **Self-contained commits**: every commit must build and pass the full check
  suite on its own, without relying on later commits.
- **Text-only repository**: never store binaries, archives, dumps, opaque blobs
  or Git LFS pointers in the repo; see [Source artifact policy](#source-artifact-policy).
  Keep build outputs in ignored `target/` and scratch files in ignored `tmp/`
  or the system temp directory.
- **Rust-first tooling**: project-owned code, tests and tools are Rust, with
  Cargo aliases for routine checks—avoid extra helper scripts or runtimes. The
  thin Bash/Zsh completion adapters under `share/` are the only exception
  (argument selection and data access stay in Rust).
- **Cryptography stack**: GotaTun with the non-FIPS `aws-lc-rs` backend is the
  approved stack (its bundled AWS-LC C build is an explicit exception to the
  Rust-only dependency rule). Review any new dependencies, features and build
  scripts carefully.
- **Core invariants**: keep `main` authoritative and `child` forwarding
  independent of `main` availability. Preserve per-user isolation, standard
  WireGuard client compatibility and durable configuration.
- **Tests and reviews**: encode checkable rules in compiler/linter config or
  tests. For behavior changes, write a failing test first with expectations
  independent of the implementation; never weaken tests to hide failures.
  Runtime and security changes require independent review noting behavior,
  verification and remaining limitations.
- **Minimal diffs**: prefer existing abstractions and avoid unrelated cleanup.

When using coding agents, follow the repository skills under
[.agents/skills/](../.agents/skills/) and session instructions. Agent Git
access is limited to `git diff --no-ext-diff --no-textconv` (without
output-to-file flags). Repository state belongs to the user; do not install Git
hooks, execute `sudo`, or perform unauthorized downloads, installs or
service/container changes.

## Licensing

Contributions to project-owned code and documentation use `AGPL-3.0-only`; see
[LICENSE](../LICENSE). Adapted [skills](../.agents/skills/) retain their own
licenses—preserve upstream notices and record source revision, author and local
changes in each skill's `PROVENANCE.md`.

## Prepare a development machine

Use Linux x86-64 with glibc (CI runs on Ubuntu 24.04; server deployment steps
are in [Getting started](GETTING_STARTED.md)). Start from a complete checkout
including hidden config directories (`.cargo/`, `.github/`, `.agents/`),
`Cargo.lock` and `share/`.

On Debian/Ubuntu, install system prerequisites as root:

```sh
apt-get update
apt-get install --no-install-recommends build-essential ca-certificates curl bash zsh
```

`build-essential` compiles the bundled non-FIPS AWS-LC C sources; `bash` and
`zsh` are used by completion integration tests. Install
[rustup](https://rust-lang.github.io/rustup/installation/) using its official
instructions, then run the remaining setup as your regular user from the
workspace root:

```sh
rustup toolchain install 1.99.0 --profile minimal --component rustfmt --component clippy
cargo --version
rustc --version
cargo fetch --locked --target x86_64-unknown-linux-gnu
```

[rust-toolchain.toml](../rust-toolchain.toml) pins the project toolchain. Re-run
`cargo fetch --locked --target x86_64-unknown-linux-gnu` whenever `Cargo.lock`
changes; all verification commands run offline from the local cache. Build and
test in a user-owned directory without group/world-writable parent directories,
as tests deliberately reject unsafe ownership and permissions.

Install the dependency auditor separately:

```sh
cargo install cargo-audit --version 0.23.0 --locked
cargo audit update-db
```

`update-db` refreshes Cargo's local RustSec advisory database (not the project
tree); re-run it before auditing. Because it runs Git internally, agents
subject to the Git restriction above must leave it to the maintainer.

## Checks and CI

Run the full check sequence from the workspace root:

```sh
cargo check-blobs &&
cargo fmt-check &&
cargo lint &&
cargo check-all &&
cargo audit-deps &&
cargo docs --check &&
cargo test --offline --locked --workspace --all-targets
```

If formatting or generated docs are out of date, update and review them, then
re-run the checks:

```sh
cargo fmt --all
cargo docs
```

Individual commands:

| Command | Purpose |
| --- | --- |
| `cargo check-blobs` | Enforce the text-only source policy (no Git or network access) |
| `cargo fmt-check` | Check Rust formatting without modifying files |
| `cargo fmt --all` | Apply Rust formatting |
| `cargo lint` | Run Clippy across the workspace and all targets (`-D warnings`) |
| `cargo check-all` | Type- and compile-check the workspace and all targets |
| `cargo audit-deps` | Audit `Cargo.lock` against the local RustSec database |
| `cargo docs` | Regenerate CLI docs, OpenAPI spec, manual page and shell adapters |
| `cargo docs --check` | Fail if any generated artifact is missing or outdated |
| `cargo test --offline --locked --workspace --all-targets` | Run workspace unit, integration and example tests |

Workspace lints forbid `unsafe` Rust and deny `dbg!`, `todo!` and
`unimplemented!`. Tests marked `#[ignore]` have explicit prerequisites and are
not run by default.

### CI workflows

- **[Checks CI](../.github/workflows/checks.yml)** runs on pushes to `main`,
  when a PR opens against a non-release branch, on manual dispatch, and weekly
  on schedule. On pushes and PRs it runs `check-blobs --checkout`, formatting,
  Clippy, workspace compile checks and `cargo audit-deps`; manual and weekly
  runs check source files and dependency advisories.
- **[Release CI](../.github/workflows/release.yml)** runs on PRs targeting
  `release` or `release/**` (`opened`, `reopened`, `synchronize`, `edited`) and
  on pushed version tags (`v[0-9]*`). After **Checks** pass, it runs in
  parallel:
  - **Release tests**: `cargo docs --check`, the full workspace test suite, and
    the ignored 105-second mesh outage recovery test.
  - **Release build (Linux x86-64)**: builds the release `wgfeel` executable
    and, on version tags, uploads the `.tar.gz` archive and `.sha256` checksum
    as a workflow artifact.
  - **Release ready**: aggregates all jobs; configure it as a required status
    check for release branches.

## Generated documentation and completions

`cargo docs` deterministically generates five checked-in artifacts from Rust
source without needing services, credentials or network access:

- [docs/docs.md](docs.md), [share/man/man1/wgfeel.1](../share/man/man1/wgfeel.1),
  [share/bash-completion/completions/wgfeel](../share/bash-completion/completions/wgfeel)
  and [share/zsh/site-functions/_wgfeel](../share/zsh/site-functions/_wgfeel)
  from [crates/host/src/help/catalog.rs](../crates/host/src/help/catalog.rs)
  (shared with `--help`).
- [docs/openapi.json](openapi.json) from the REST route definitions and wire
  types in `crates/management` (embedded in the binary and served at
  `GET /api/v1/openapi.json` with bearer authentication).

Run `cargo docs` and `cargo docs --check` whenever you change CLI commands,
options, help text, completion adapters, REST routes or wire types. Files are
rewritten only when their content changes. For end-user `man` and shell
completion usage, see [Getting started](GETTING_STARTED.md#manual-and-shell-completion).

## Release build and offline audit

To build the release executable from cached dependencies:

```sh
cargo build --release --locked -p wgfeel --bin wgfeel
```

`cargo audit-deps` checks `Cargo.lock` against the local RustSec database
(`$CARGO_HOME/advisory-db` or `~/.cargo/advisory-db`; override with
`cargo audit-deps --db /path/to/advisory-db`). Vulnerabilities and advisory
warnings fail the check, and no advisories are ignored. Because it runs offline
and skips yanked-crate checks, a passing result reflects only the freshness of
your local advisory copy.

## Source artifact policy

[tools/check-blobs/src/main.rs](../tools/check-blobs/src/main.rs) inspects
files directly on disk (including hidden files and `.agents/skills/`) without
reading Git's index or `.gitignore`.

Enforced rules:

- Regular UTF-8 text files only; symlinks, special files and binary control
  characters (other than tab, CR and LF) are rejected.
- Allowed extensions: `.rs`, `.toml`, `.lock`, `.md`, `.txt`, `.json`, `.yml`,
  `.yaml`, `.bash`, `.zsh`, `.1`. Named exceptions: `LICENSE`, `COPYING`,
  `NOTICE`, `README`, `Dockerfile`, `Containerfile`, `.gitignore`,
  `.gitattributes`, `.dockerignore`, `.editorconfig`, `.env.example`, and the
  two completion files under `share/`.
- Limits: at most 1 MiB (1,048,576 bytes) per file and 16 KiB (16,384 bytes)
  per line. Generate large test fixtures at runtime.
- Git LFS pointers are rejected regardless of extension.

Local runs skip only fixed workspace-root local paths (build/scratch folders,
editor/agent configs, caches and local runtime directories); nested directories
with those names are still checked. `--checkout` (used by CI on a clean
checkout) rejects those root paths as well so ignored local artifacts cannot be
force-committed.

## Repository layout

| Path | Contents |
| --- | --- |
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` | Workspace definition, locked dependencies and toolchain pin |
| `crates/` | Application crates, integration tests and Rust examples |
| `tools/` | Project-owned Rust development tools (`check-blobs`) |
| `.cargo/` | Cargo aliases, AWS-LC build env and offline audit config |
| `.github/workflows/` | Static checks, dependency audit and release workflows |
| `README.md`, `LICENSE`, `.gitignore`, `docs/` | Overview, license, guides, generated CLI/OpenAPI docs and backlog |
| `share/` | Generated manual page and Bash/Zsh completion resources |
| `.agents/skills/` | Adapted agent skills with licenses and provenance records |

Keep build outputs (`target/`), scratch files (`tmp/`), editor/agent configs,
local state, backups, logs, invitations and private keys out of commits. Always
keep `Cargo.lock` and generated docs in sync with code changes.

## Verification scope

Report static checks, automated tests and real-host deployment checks
separately. Installation tests use temporary roots with `--no-start`, and
runtime tests run foreground processes—they do not verify real systemd
integration, host reboots or production load. Three-node tests use GotaTun
peers with native-format configs, with a separate Linux WireGuard
interoperability fixture. Ignored or environment-dependent tests must be run
explicitly before claiming their coverage.

[README](../README.md) · [Getting started](GETTING_STARTED.md) ·
[Security policy](SECURITY.md) · [Backlog](BACKLOG.md)
