---
name: cdb-native-validation
description: Validate debugger-backed Windows native vulnerability claims with CDB or WinDbg while separating product behavior from route, timing, heap, and debugger-policy effects. Use when a native candidate, first-bad-state, lifetime or heap claim, or native negative needs debugger evidence. Do not use for discovery-only or source-only work.
---

# CDB native validation

Apply only when promoting a debugger-backed dynamic claim. Keep discovery free to choose other tools.

## Classify the observation mode

- `NATIVE`: Reproduce the authoritative input route without a debugger or verifier.
- `MINIMAL_OBSERVER`: Use the least intrusive CDB mode and observer-only breakpoints that preserve that route.
- `INSTRUMENTED`: Use settings such as debug heap, PageHeap, AppVerifier, broad watchpoints, or changed event policy that may alter behavior.
- `MUTATING`: Change registers, memory, control flow, or objects only to discriminate a hypothesis.

Never merge results from different modes into one native claim.

## Validation contract

1. Fix the exact product, build, architecture, module/input hashes, profile or options, and authoritative input-delivery route.
2. Run native control and candidate in fresh processes; record route and outcome as the baseline.
3. Choose the least intrusive observer. Run its control first and require equivalent module, dispatch route, important callsites, object state, and termination behavior.
4. Run the observed candidate with the same configuration and capture the pre-instruction first-bad-state.
5. If behavior differs, change one variable at a time: creation/attach, initial open/post-init handoff, heap mode, break/event policy, breakpoint timing, verifier/IFEO, child process, inherited handles or privileges, environment, working directory, profile, or recovery state.
6. Repeat in a fresh process and input namespace, then restore owned debugger, verifier, environment, option, and staging changes.

Treat attach and `-hd` as variables, not universal fixes. Keep observation-mismatch cause separate from product root cause.

## Bound divergent and mutating results

- If the observed control does not preserve the native route, promote no positive or negative from that configuration.
- Label a crash or clean exit seen only under instrumentation as `INSTRUMENTED_ONLY_POSITIVE` or `INSTRUMENTED_ONLY_NEGATIVE`.
- Label an unresolved route mismatch as `BLOCKED_INSTRUMENTATION_DIVERGENCE`; do not close the product path as a native negative.
- Keep PageHeap/AppVerifier results separate from ordinary allocator behavior.
- Mark breakpoint commands as observer-only or state-changing. Mutation does not prove a natural trigger or attacker control.
- Infer no exploitability from debugger-created layout, forced state, or failed cleanup alone.

## Evidence and result

Capture exact identities, routes, settings, breakpoint order, repeat outcomes, pre-instruction registers/stack/memory, file-control linkage, remaining inference, raw evidence pointers, and cleanup proof.

Return only:

- `native_baseline`
- `observed_mode_and_route_equivalence`
- `isolated_variables`
- `first_bad_state`
- `primitive_and_file_control`
- `instrumented_or_mutating_results`
- `supported_refuted_unknown`
- `evidence_pointers`
- `next_discriminating_test`

Keep static lead, reachability, trigger/crash, primitive, attacker control, exploitability, RCE, novelty, and reportability separate. Do not take external or weaponization action without explicit approval.

Read [references/cdb-commands.md](references/cdb-commands.md) only for command patterns and option details.
