# Project scope

- Use this repository for real-world vulnerability research, not CTF solving. Never load or cite a `ctf-*` skill here.
- For closed-source discovery, use only `research/active/closed-source-rce/DISCOVERY-PROMPT.md`. Retired pipelines are historical references, not workflows.
- Keep the repository-root `AGENTS.md` target-independent.
- `research/active/closed-source-rce/DISCOVERY-PROMPT.md` owns the current product, input scope, exclusions, completion condition, and shared-tool ownership.
- A target instance is the corresponding directory under `research/active/closed-source-rce/` that stores the target's PoCs and controls plus its `evidence/`, `observation/`, `findings/`, and `llm-log.md`.
- When the target changes, update that prompt and create or switch the target instance; do not make the root `AGENTS.md` or shared runtime target-specific.
- Let the analyzing agent choose functions, inputs, IDA queries, and experiments. Do not recreate stage lists, queues, roles, or coverage machinery.
- Existing findings may seed hypotheses, but the same root cause at the same exploitability boundary is not a new discovery. Expanding that boundary toward a live target, stronger file control, or a concrete chain is continued development, not duplicate discovery.

# Evidence and claims

- Before promoting a dynamic claim, fix the exact product, build, architecture, module and input hashes, delivery route, PoC, and matched control.
- Treat decompiler output as a hypothesis; assembly and reproducible native execution are ground truth.
- Keep static lead, reachability, trigger/crash, primitive, file control, exploitability, RCE, novelty, and reportability separate.
- Load `$cdb-native-validation` only when a Windows native candidate needs debugger-backed claim validation. CDB is not a required discovery stage.
- Debugger configuration and observation mode can alter route, timing, heap, or state. Treat each change as an experimental variable; promote no debugger-only or route-divergent result without a native baseline and a route-equivalent observed control.
- Label debugger commands that change registers, memory, control flow, or objects as `MUTATING`. They may distinguish hypotheses but do not prove a natural file trigger or attacker control.
- Scope every negative to the tested build, function or callsite, input mode, route, and observation window; never generalize it to the product as a whole.

# Evidence storage

- Raw logs, dumps, PoCs, controls, commands, hashes, observations, and same-day `llm-log.md` entries are canonical evidence.
- After writing `observation/OBS-*.yaml`, append a same-day block to that target's `llm-log.md`. SecondBrain does not replace it.
- Treat `research/.agent-state/` checkpoints, capsules, caches, and indexes as disposable derived runtime state. They may support context recovery but never serve as evidence for a product or vulnerability claim.
- Create a finding card only after a repeated native primitive or evidence-bounded root cause. Retrieve cards only for primitive promotion or an explicit chain review.
- Keep active prompts, target instances, evidence, observations, findings, `llm-log.md`, PoCs, controls, corpora, dumps, vendor files, IDA databases, credentials, and session material out of the shared Git history.
- Promote only target-independent code, documentation, schemas, tests, and deliberately synthetic fixtures after repository preflight.
