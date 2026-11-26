---
name: property-based-testing
description: Design, review, or debug meaningful property-based tests for wgfeel Rust parsers, codecs, validation, arithmetic, and state invariants when the requested task benefits from generated inputs.
license: CC-BY-SA-4.0
metadata:
  upstream-author: Henrik Brodin
  upstream: https://github.com/trailofbits/skills
  upstream-revision: 149d7b21f4067765b82e67029730b42d228ef4b4
  adaptation: "Self-contained Rust property-testing subset"
---

# Property-based tests for wgfeel

Adapted from Henrik Brodin's `property-based-testing` guidance in Trail of Bits'
skills repository. This adapted document is licensed under CC BY-SA 4.0; retain
[LICENSE](LICENSE) and [PROVENANCE.md](PROVENANCE.md).

## Scope

User instructions and applicable AGENTS.md govern scope, permissions, Git,
dependencies, and testing. Review requests remain read-only. This skill grants
no tool permissions and does not authorize downloads, new dependencies, service
changes, extra agents, refactoring, or broader tests by itself. It does not change
the session's model or reasoning settings. Source links are attribution only.

Keep implementation and project tooling Rust-only. First inspect the existing
testing approach. Reuse the existing property-testing library if one is present;
proptest and quickcheck are options, not installation requirements. If a new
library is justified, explain the concrete property and obtain any required
dependency approval before changing Cargo files or fetching packages.

## Select a useful property

Ground expectations in the intended project contract, independently of the current
implementation. Suitable properties include:

- Codec roundtrips for valid domain values, together with independent format
  examples and malformed-input rejection. Encoder and decoder can share a bug;
  roundtrips alone do not establish correctness or interoperability.
- Idempotence where the contract promises normalization or repeated application
  without further change; do not assume all operations are idempotent.
- Independent reference results or explicit invariants for arithmetic and bounds.
- Rejection of unauthorized tenant/source combinations, stale revisions, or
  invalid policy without granting access or partially changing durable state.

Choose properties relevant to the requested change. Example tests are appropriate
when generated inputs add little value. No-crash checks may complement semantic
properties, but do not establish authorization or protocol correctness.

## Generate and check inputs

1. Encode valid-domain constraints in bounded generators, including dependent
   fields. Avoid excessive filtering that leaves little meaningful coverage.
2. Exercise invalid inputs separately against the documented rejection contract.
   Include deterministic cases for empty, zero, maximum, truncated, malformed,
   duplicate, and conflicting values where relevant.
3. Bound input sizes, cases, runtime, memory, and external effects. Use isolated
   local fixtures and synthetic secrets; generated cases must not contact live
   peers, modify host networking, or expose real credentials.
4. Assert observable contract outcomes, not a restatement of the implementation.
   Check that assertions are reachable and generated cases actually run. Treat
   exhausted filters, skipped cases, and missing assertions as coverage failures.
5. Preserve a minimal failing input as a deterministic regression case. Record the
   seed or replay data when available, without storing secrets or unbounded blobs.

## Interpret failures

Distinguish an implementation bug, a wrong property/generator, and an ambiguous
contract. Derive a correction from independent requirements; never weaken an
assertion or discard a counterexample just to obtain a passing run. Explain
uncertainty and ask for a contract decision when needed. A refactor to expose a
test seam must be justified and within the user's authorized scope.

Report the property, input domain, concrete failing case or results, and coverage
limits. Local generated tests do not prove live WireGuard interoperability,
multi-host isolation, or deployment behavior.
