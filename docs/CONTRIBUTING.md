# Contributing

Keep changes focused and preserve existing behavior outside the requested scope.
For security-sensitive work, follow the [security policy](SECURITY.md).

## Development rules

- Every commit must build successfully and pass the test suite described below.
  Each commit must satisfy this independently, without relying on later fixes.
- Keep the source repository text-only. Do not store compiled executables,
  libraries, archives, binary assets, database dumps, opaque payload blobs or
  Git LFS payload pointers in it. Empty or textual stand-ins for binary artifacts
  are also forbidden. Build executable artifacts from source; generate test data
  deterministically at runtime in disposable storage or as bounded streams.
  Keep local build outputs under ignored `target/` and scratch data under ignored
  `tmp/` or the system temporary directory. These directories must not be published.
- Project-owned executable code, tests and automation are Rust. Use Cargo
  configuration for simple checks; avoid helper scripts or new runtimes.
  The small Bash/Zsh completion adapters are an exception: they call the native
  shell completion APIs; argument selection and data access remain in Rust.
- GotaTun with the non-FIPS `aws-lc-rs` backend is the approved cryptography stack.
  Its native AWS-LC build is an explicit exception to the Rust-only dependency
  constraint. Review new dependencies, transitive features and build scripts.
- Keep main authoritative and forwarding on children independent of main availability.
  Preserve user isolation, standard WireGuard client compatibility, durable
  configuration and operation during Management outages.
- Encode mechanically checkable requirements in compiler/linter rules or tests.
  For behavior changes, write a meaningful failing test first. Keep expected
  results independent of the implementation; never weaken tests to hide a failure.
- Use focused tests for concrete risks. Documentation and simple declarative
  changes do not need artificial tests. Runtime/security changes need independent
  review; describe behavior, verification and remaining limitations.
- Prefer minimal changes and existing abstractions. Avoid unrelated cleanup.

When using coding agents, follow applicable AGENTS.md and session instructions.
Git access for agents is limited to `git diff --no-ext-diff --no-textconv`, without
output-to-file options. Repository-state management belongs to the user; do not
install Git hooks. Downloads, installation, privileged actions and service/container
changes require the applicable authorization. Agents must not execute `sudo`.

## Licensing

Contributions to project-owned code and documentation are under `AGPL-3.0-only`;
see [LICENSE](../LICENSE). Adapted [skills](../.agents/skills/) retain their
separate licenses. Preserve upstream notices and record the source revision,
author and local changes in each skill's `PROVENANCE.md`.

## Prepare a development machine

Use Linux x86-64 with glibc. CI uses Ubuntu 24.04; deployment instructions are in
[Getting started](GETTING_STARTED.md). Obtain the complete source tree, including
hidden configuration directories, `Cargo.lock` and `share/`, then enter its root.

On Debian/Ubuntu, install these packages as root. This changes system packages;
it is a separate setup step, not part of the checks:

```sh
apt-get update
apt-get install --no-install-recommends build-essential ca-certificates curl bash zsh
```

The C toolchain builds the bundled non-FIPS AWS-LC source. Bash and Zsh are used by
completion integration tests. Install [rustup](https://rust-lang.github.io/rustup/installation/)
using its official instructions, then open a shell with Cargo on `PATH`. Run the
remaining commands as your ordinary development user, from the workspace root:

```sh
rustup toolchain install 1.99.0 --profile minimal --component rustfmt --component clippy
cargo --version
rustc --version
cargo fetch --locked --target x86_64-unknown-linux-gnu
```

[rust-toolchain.toml](../rust-toolchain.toml) selects the project toolchain.
The explicit fetch downloads the locked dependencies; repeat it after changing
`Cargo.lock`. Subsequent checks use the cache and never update the lockfile.
Build and test in a directory owned by your user with no writable shared parents;
the tests deliberately reject unsafe filesystem ownership and permissions.

Prepare the dependency auditor separately:

```sh
cargo install cargo-audit --version 0.23.0 --locked
cargo audit update-db
```

Installation downloads and builds the auditor into Cargo's tool directory.
`update-db` explicitly fetches the official RustSec advisory repository into
Cargo's cache; it updates that separate database, not the project. Repeat this
step before an audit to check against current advisories. It performs Git
operations internally, so an agent subject to the Git restriction above must
leave it to the maintainer. Neither command is part of `cargo audit-deps`.

## Build and checks

From the workspace root, run the checks in order. `&&` stops at the first failure:

```sh
cargo check-blobs &&
cargo fmt-check &&
cargo lint &&
cargo check-all &&
cargo audit-deps &&
cargo docs --check &&
cargo test --offline --locked --workspace --all-targets
```

If formatting or generated documentation is outdated, update it explicitly,
review the changes, then repeat the checks:

```sh
cargo fmt --all
cargo docs
```

[GitHub CI](../.github/workflows/checks.yml) builds, lints, tests and checks
documentation when a pull request is opened, on pushes to `main`, and on pushes
of release tags such as `v0.1.0`. Manual and weekly runs check source files and
dependency advisories. The first job checks the fresh checkout for forbidden
artifacts. Build, lint, tests and dependency auditing depend on that job
succeeding. The checker uses only the Rust standard library. CI compiles it with
`rustc` into the runner's temporary directory before fetching Cargo dependencies
or creating project build outputs.
CI installs prerequisites in disposable runners and refreshes RustSec separately,
then reports check failures without regenerating tracked files, applying fixes, committing or
publishing artifacts. The repository token has read-only contents access and is
not retained by checkout. No Git hooks are used. Checks still create build outputs
and temporary test fixtures. Ignored native/long-running acceptance tests are not
enabled by CI. Workspace tests include unit tests and the existing local process
integration tests. The future container-based functional/load environment is not
part of this workflow.

All development commands can also be run individually:

| Command | Purpose |
| --- | --- |
| `cargo check-blobs` | Reject forbidden source artifacts before formatting, linting or testing. No Git commands or network access. |
| `cargo check-all` | Compile-check the workspace and all targets, including tests. |
| `cargo lint` | Run Clippy for the workspace and all targets; warnings are errors. |
| `cargo fmt-check` | Report formatting differences without editing files. |
| `cargo fmt --all` | Explicitly apply Rust formatting. |
| `cargo audit-deps` | Check locked dependencies against the local RustSec database. |
| `cargo docs` | Regenerate the CLI reference, OpenAPI document, man pages and shell adapters. |
| `cargo docs --check` | Report missing or outdated generated documentation. |
| `cargo test --offline --locked --workspace --all-targets` | Run workspace unit and integration tests, including examples. |

Workspace rules forbid unsafe Rust and reject `dbg!`, `todo!` and
`unimplemented!` through Clippy. Tests marked `#[ignore]` require their explicit
acceptance procedure; the command above does not enable them automatically.

## Source artifact policy

[The checker](../tools/check-blobs/src/main.rs) examines files on disk, including
hidden files and shared skills. It does not read Git's index or use `.gitignore`
to hide arbitrary paths. Run it from the workspace root before other checks.

The mechanically enforced rules are:

- Files must be regular UTF-8 text without control characters other than tab,
  carriage return and newline. Symlinks and special files are rejected.
- Allowed extensions are `.rs`, `.toml`, `.lock`, `.md`, `.txt`, `.json`, `.yml`,
  `.yaml`, `.bash`, `.zsh` and `.1`. Named exceptions cover `LICENSE`, `COPYING`,
  `NOTICE`, `README`, `Dockerfile`, `Containerfile`, `.gitignore`, `.gitattributes`,
  `.dockerignore`, `.editorconfig`, `.env.example`, and the two generated native
  shell completion resources under `share/`.
- A file may contain at most 1 MiB (1,048,576 bytes), and a line at most 16 KiB
  (16,384 bytes). Large fixtures and embedded payloads belong in runtime generators.
- Git LFS payload pointers are rejected, even when renamed to a text extension.
- Unsupported artifact names are rejected even when their contents are empty or
  happen to be text. Renaming a binary to `.rs` or `.md` does not bypass content
  checks. Small source-level packet vectors used by parser tests remain ordinary
  source code; the checker is not a semantic classifier of arbitrary encoded data.

Local runs skip only the fixed workspace-root exclusions listed in the checker:
build/scratch directories, private runtime data, agent/editor settings and caches.
Nested directories with those names are still checked. `.agents/skills` is checked.
The checker reports paths and reasons, never file contents, and never edits files.

`--checkout` is for a fresh source-only checkout: it rejects all those local-only
roots instead of skipping them, so a force-added ignored artifact cannot bypass
CI. `.git` metadata is excluded in both modes. CI runs this mode before creating
any project outputs. No Git hooks are installed. Extending the accepted source
formats requires an explicit checker change and review; renaming an opaque blob
to an allowed extension does not make it acceptable under the project policy.

## Command reference

The static [command reference](docs.md), man pages and terminal `--help` share the Rust
descriptions in [crates/host/src/help](../crates/host/src/help/catalog.rs).
When changing a command, keep its description, options and examples consistent
with the parser and behavior, then regenerate the reference:

```sh
cargo docs
cargo docs --check
```

`cargo docs` also generates the [OpenAPI document](openapi.json) from the REST
routes and wire types. The server embeds this file and serves it at
`GET /api/v1/openapi.json` with bearer authentication.

The same command refreshes `docs/docs.md` and the resources in [share](../share/),
including section-1 manuals, Bash adapters and Zsh completion functions. Keep these static
files with the code. Files are replaced only when their generated content changes.
`--check` fails if any artifact is missing or outdated and never writes files.
Generation is deterministic, uses cached dependencies, and requires no running
services, credentials or network access. Run these commands when changing
CLI documentation, completion adapters, REST routes or their wire types.

## Manuals and shell completion

Common installation writes its resources as ordinary mode-0644 files:

| Resource | Installed location |
| --- | --- |
| Manual | `/usr/local/share/man/man1/wgfeel.1` |
| Bash | `/usr/local/share/bash-completion/completions/wgfeel` |
| Zsh | `/usr/local/share/zsh/site-functions/_wgfeel` |

Use `man wgfeel`.
Bash loads the adapters through
`bash-completion`; Zsh loads them from `fpath` after `compinit`. If the shell is
already running, or no completion loader is configured, enable the relevant
adapter explicitly in that shell:

```bash
source <(wgfeel completions bash)
```

```zsh
autoload -Uz compinit
compinit
source <(wgfeel completions zsh)
```

Put the relevant setup in your shell configuration for future sessions. Bash and
Zsh are supported; other shells need their own native adapters. Updates refresh
the installed instance's resources. Uninstall removes only receipt-owned files;
modified or unrelated files are preserved and reported as conflicts.

Tab completes command names, flags, supported fixed values and file paths.
Management additionally suggests existing users, devices and Nodes where an ID
is accepted, including `device add --user`. Zsh displays names beside IDs; Bash
inserts and lists IDs. Dynamic completion uses the usual local credentials or
explicit connection options (`--profile`, or `--socket` with `--credential-file`).
It makes authenticated read-only requests with a 500 ms local deadline (3 seconds
for a remote profile, including the fresh WireGuard/TCP session), never
dispatches the typed operation, and quietly returns no dynamic candidates when
Management is unavailable or access is denied. Static completion remains usable.
Dynamic data is not cached in generated documentation or shell scripts.

## Release build and dependency audit

Compiler, lint and test commands use cached dependencies and preserve
`Cargo.lock`. To build release artifacts:

```sh
cargo build --release --locked -p wgfeel --bin wgfeel
```

`cargo audit-deps` requires an installed `cargo-audit` and a populated local
RustSec database, normally `$CARGO_HOME/advisory-db` or `~/.cargo/advisory-db`.
Use `cargo audit-deps --db /path/to/advisory-db` for a different location.
It checks `Cargo.lock` for RustSec advisories, including CVE-linked entries;
vulnerabilities and advisory warnings fail the check. No advisories are ignored.

The audit performs no database fetch or registry-index update and skips yanked
release checks. Maintain the database separately: a passing offline audit covers
only that copy and does not establish its freshness.

## Files for the first public commit

Include these project files, including hidden directories:

| Path | Contents |
| --- | --- |
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` | Workspace, locked dependencies and toolchain. |
| `crates/` | Product code, tests and Rust examples. |
| `tools/` | Project-owned Rust development tools, including the source artifact checker. |
| `.cargo/` | Build, lint and offline audit configuration. |
| `.github/workflows/` | Checks only; no release or deployment workflow. |
| `README.md`, `LICENSE`, `.gitignore`, `docs/` | Entry points, license, guides, generated reference and backlog. |
| `share/` | Generated man pages and Bash/Zsh completion resources. |
| `.agents/skills/` | Selected skills with their own licenses, attribution and provenance. |

Keep build outputs, `tmp/`, editor files, `.codex/`, `.aws/`, local environment
files, installed state, backups, logs, invitations and private client/admin exports
out of the commit. `.gitignore` covers common local paths and private file types;
store other private material outside the source tree. It does not remove files
already tracked or recognize secrets pasted into source. Review the actual files
selected for publication and their contents before committing. Repository-state
management and the commit itself belong to the maintainer.

Keep `Cargo.lock` and generated documentation in the commit. Run the checks above
and the release build before publication.

## Verification scope

Report static checks, unit/integration tests and real deployment evidence
separately. Installation tests use temporary roots and `--no-start`;
runtime tests explicitly launch foreground processes. These checks do not
prove systemd installation, reboot behavior or production capacity.

The three-Node service tests use GotaTun peers with native-format configurations;
a separate Linux WireGuard fixture checks interoperability. Ignored or
environment-dependent tests require explicit execution and their prerequisites
before claiming that coverage.

[README](../README.md) · [Security policy](SECURITY.md) · [Backlog](BACKLOG.md)
