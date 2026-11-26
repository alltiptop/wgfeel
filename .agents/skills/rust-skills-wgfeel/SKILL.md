---
name: rust-skills-wgfeel
description: Apply a curated subset of Leonardo's Rust guidance when writing or reviewing wgfeel Rust code, especially boundary validation, secret handling, arithmetic, concurrency, and measured performance changes.
license: MIT
metadata:
  upstream-author: Leonardo Maldonado
  upstream: https://github.com/leonardomso/rust-skills
  upstream-revision: fd2a861ab0406a4ac536a55274d14ea6fd1ca9c9
  upstream-version: "1.5.1"
  adaptation: "12 selected rules, condensed and qualified for wgfeel"
---

# Rust guidance for wgfeel

Apply only the rules relevant to the requested change. This is a local adaptation
of Leonardo Maldonado's guidance, not the complete upstream skill. It is
self-contained; the pinned source links are optional attribution and references.
The upstream MIT notice is retained in [LICENSE](LICENSE); source attribution
and local changes are recorded in [PROVENANCE.md](PROVENANCE.md).

## Project context

Use the current project-root `README.md`, `Cargo.toml`, and relevant contracts in
`implementation_plan.md` to resolve applicability. Existing user and repository
instructions govern scope, permissions, Git operations, dependencies, and tests.
This skill does not authorize installations, automatic updates, or broader edits.

Preserve tenant/source/ACL isolation, recipient-specific secret ownership,
Management as configuration authority, durable policy activation, and Node
operation without Management. Keep the existing runtime, workspace boundaries,
Rust-only tooling policy, and `unsafe_code = "forbid"`. Generic advice must not
weaken these contracts or imply that unit tests prove live network behavior.

## Selected rules

1. **Borrow when ownership is unnecessary.** Prefer borrowed inputs for read-only
   work. Clone only when ownership or lifetime requirements justify it; not every
   clone allocates. Do not share tenant-private state across confinement boundaries
   merely to avoid a copy. Source: [own-borrow-over-clone](https://github.com/leonardomso/rust-skills/blob/fd2a861ab0406a4ac536a55274d14ea6fd1ca9c9/rules/own-borrow-over-clone.md).

2. **Return errors for expected failures.** Handle malformed input, network/storage
   failure, and invalid configuration through the project's existing error types.
   Propagating an error must preserve the specified rollback or fail-closed behavior;
   do not replace invalid security policy with permissive defaults. Source:
   [err-result-over-panic](https://github.com/leonardomso/rust-skills/blob/fd2a861ab0406a4ac536a55274d14ea6fd1ca9c9/rules/err-result-over-panic.md).

3. **Keep identities and validated values distinct.** Reuse domain newtypes to
   prevent mixing network, device, and node identities. Constructors must enforce
   their invariants. Derive only traits valid for the representation and security
   contract: a `String` wrapper cannot be `Copy`, and secret wrappers need redacted
   diagnostics. Source: [api-newtype-safety](https://github.com/leonardomso/rust-skills/blob/fd2a861ab0406a4ac536a55274d14ea6fd1ca9c9/rules/api-newtype-safety.md).

4. **Validate on deserialization.** A validated constructor is insufficient if
   derived `Deserialize` bypasses it. Use the existing custom deserializer or a
   fallible conversion such as `#[serde(try_from = "Raw")]`. Enforce input size
   bounds before allocating or parsing; validation afterward does not bound memory.
   Source: [serde-try-from-validate](https://github.com/leonardomso/rust-skills/blob/fd2a861ab0406a4ac536a55274d14ea6fd1ca9c9/rules/serde-try-from-validate.md).

5. **Reject unknown fields where the contract is strict.** Use
   `deny_unknown_fields` for strict inputs when compatible with the protocol and
   persisted-state migration policy. Preserve deliberately extensible formats.
   Unknown fields and missing required fields are separate cases; Serde does not
   implicitly default a missing required integer to zero. Do not combine this
   attribute with `flatten`. Source: [serde-deny-unknown-fields](https://github.com/leonardomso/rust-skills/blob/fd2a861ab0406a4ac536a55274d14ea6fd1ca9c9/rules/serde-deny-unknown-fields.md).

6. **Choose overflow behavior explicitly.** Use checked arithmetic for lengths,
   offsets, limits, and revisions where overflow invalidates the operation.
   Saturation or wrapping is appropriate only when the contract requires it;
   neither may silently bypass a quota or make a stale revision appear fresh.
   Source: [num-overflow-explicit](https://github.com/leonardomso/rust-skills/blob/fd2a861ab0406a4ac536a55274d14ea6fd1ca9c9/rules/num-overflow-explicit.md).

7. **Make narrowing conversions fallible.** Prefer `From` for supported lossless
   integer conversions and `TryFrom` for narrowing or signedness changes that can
   fail. Check wire lengths and indices before using them. Source:
   [num-cast-try-from](https://github.com/leonardomso/rust-skills/blob/fd2a861ab0406a4ac536a55274d14ea6fd1ca9c9/rules/num-cast-try-from.md).

8. **Justify atomic ordering.** Distinguish independent counters from flags that
   publish other state. Relaxed operations alone do not publish that state. Keep
   existing synchronization unless a documented ordering argument and relevant
   concurrency evidence justify changing it. Do not introduce unsafe shared state
   or weaken ordering solely for speed. Source: [conc-atomic-ordering](https://github.com/leonardomso/rust-skills/blob/fd2a861ab0406a4ac536a55274d14ea6fd1ca9c9/rules/conc-atomic-ordering.md).

9. **Keep secrets out of diagnostics.** Cover logs, error chains, `Debug`, and
   `Display`. Never record private keys, tokens, invitations, or full sensitive
   request/configuration bodies. Use existing secret wrappers and logging
   facilities; redaction does not replace the project's zeroization requirements.
   Source: [obs-no-sensitive-data](https://github.com/leonardomso/rust-skills/blob/fd2a861ab0406a4ac536a55274d14ea6fd1ca9c9/rules/obs-no-sensitive-data.md).

10. **Measure before optimizing.** Establish a representative baseline and compare
    one change at a time. Include small/idle deployments as well as stress loads.
    A measured hotspot does not by itself justify a new dependency, non-resistant
    hasher for untrusted input, changed panic policy, or compiler-profile change.
    Source: [perf-profile-first](https://github.com/leonardomso/rust-skills/blob/fd2a861ab0406a4ac536a55274d14ea6fd1ca9c9/rules/perf-profile-first.md).

11. **Reuse buffers within ownership and memory limits.** Reuse allocations when
    measurement supports it, keeping capacities bounded and tenant isolation
    intact. `clear()` retains capacity and is not secure erasure; preserve secret
    cleanup and lifetime guarantees. Source: [mem-reuse-collections](https://github.com/leonardomso/rust-skills/blob/fd2a861ab0406a4ac536a55274d14ea6fd1ca9c9/rules/mem-reuse-collections.md).

12. **Keep abstractions proportionate.** Introduce traits or generics for concrete
    reuse, necessary testing seams, or an actual contract. Avoid speculative
    frameworks, and preserve existing isolation and test boundaries even when
    there is only one production implementation. Source:
    [anti-over-abstraction](https://github.com/leonardomso/rust-skills/blob/fd2a861ab0406a4ac536a55274d14ea6fd1ca9c9/rules/anti-over-abstraction.md).

## Validation

Follow the existing project test policy. For behavior changes, derive acceptance
cases from the requirement and failure scenario, preserve independent expectations,
and exercise the affected boundary. Run focused checks for the supported feature
configuration; do not blindly enable all features. Report the checks performed
and any missing runtime, interoperability, or deployment evidence.
