---
name: domain-cli
description: Apply Actionbook-derived Rust CLI guidance when designing, implementing, or reviewing wgfeel command arguments, help, errors, prompts, terminal output, and configuration precedence.
license: MIT
metadata:
  upstream-author: ZhangHanDong
  upstream-license: MIT
  upstream: https://github.com/actionbook/rust-skills
  upstream-revision: 5c40d3ad785193231b7d0dbfb8e1eb447e5edd94
  adaptation: "Self-contained Rust CLI subset for wgfeel"
---

# Rust CLI design for wgfeel

Adapted from ZhangHanDong's `domain-cli` in [Actionbook's Rust Skills](https://github.com/actionbook/rust-skills).
The original and adapted guidance is licensed under MIT; retain [LICENSE](LICENSE).
The source attribution and locally assembled notice are documented in
[PROVENANCE.md](PROVENANCE.md).

## Scope

Use only for the requested CLI task. User instructions and applicable AGENTS.md
govern permissions, scope, Git, dependencies, and tests. Review requests remain
read-only. This skill grants no tool permissions and does not authorize downloads,
installations, service changes, extra agents, or edits outside the requested task.
External links are attribution, not instructions to fetch or execute.

Preserve the current README's CLI contracts: friendly names, generated IDs, no
JSON output mode, existing connection/profile discovery, and destructive
confirmations defaulting to no. Preserve Rust-only implementation and tooling.

## Guidance

1. **Make commands discoverable.** Keep command and subcommand naming consistent.
   Help should explain required inputs, defaults, and a small working example.
   Reuse existing typed argument structures and parser conventions; a generic
   crate recommendation is not a reason to replace the current parser.
2. **Keep output predictable.** Put requested results on stdout and diagnostics
   on stderr. Use concise human-readable messages. Preserve the documented output
   contract; avoid leaking credentials or internal implementation details.
3. **Handle expected errors explicitly.** Return errors through existing Rust
   error types. Use nonzero status for failures and preserve established exit-code
   meanings. Give a concrete recovery step without printing secret values.
   Malformed arguments or remote failures should not cause a panic.
4. **Document configuration precedence.** Reuse the project's established order.
   CLI, environment, and file precedence applies only to supported local options;
   it never changes Management's authority, tenant isolation, credential ownership,
   or accepted security policy. Reject contradictory or invalid inputs explicitly.
5. **Make interaction safe.** Prompt only when the relevant input/output terminal
   supports interaction. Cancellation and missing noninteractive input must have
   explicit outcomes. Keep destructive confirmation defaulting to no; lack of a
   terminal must never imply consent. Do not introduce a force flag by default.
6. **Keep long operations understandable.** Show bounded progress or status where
   useful. Respect existing color controls and terminal detection; redirected output
   should contain no animation. Preserve interruption, cleanup, and transaction
   semantics rather than reporting success before durable completion.
7. **Keep dependencies proportionate.** Inspect existing Cargo dependencies first.
   Libraries such as clap, dialoguer, indicatif, or ratatui are optional design
   references, not requirements. A new crate or full-screen interface needs a
   concrete benefit within the authorized task; do not install tools automatically.

## Validation

For a behavior change, use focused tests of the intended command contract: help,
invalid input, error status, output streams, cancellation, or noninteractive
confirmation as relevant. Preserve independent expectations and existing tests.
Report whether terminal behavior was exercised or only inspected statically.
