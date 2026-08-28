# Root2PoC Codex analysis core

This repository contains the target-independent analysis loop used for authorized closed-source native vulnerability research:

```text
LLM hypothesis with IDA MCP
        -> minimal native or CDB experiment when needed
        -> observed result and explicit claim boundary
        -> next analysis decision
```

The repository shares the rules, optional debugger skill, compaction-recovery runtime, schemas, tests, and generic templates. Real targets and vulnerability evidence stay local and are never part of the shared Git history.

## Repository contents

- `AGENTS.md`: project-wide scope, evidence, and claim boundaries
- `.agents/skills/cdb-native-validation/`: optional native-debugger validation skill
- `.codex/hooks.json`: project-local context lifecycle hooks
- `research/tools/closed_source_context/`: capture, capsule, guard, retrieval, evaluation, and tests
- `research/templates/closed-source-rce/`: generic discovery prompt and target-instance templates

## Create a local target workspace

Use one active target per clone or worktree. The active prompt and target instances are intentionally ignored by Git.

```bash
mkdir -p research/active/closed-source-rce
cp research/templates/closed-source-rce/DISCOVERY-PROMPT.md \
  research/active/closed-source-rce/DISCOVERY-PROMPT.md
cp -R research/templates/closed-source-rce/target-instance \
  research/active/closed-source-rce/example-target
```

Replace the bracketed prompt fields and target metadata before analysis. Do not run these copy commands over an existing target workspace.

Start Codex from the repository root, review and trust the project hook, and verify the installation:

```bash
python3 -B -m unittest discover -s research/tools/closed_source_context/tests -v
python3 research/tools/repository_preflight.py
```

The preflight checks the Git index, so it becomes meaningful after files have been staged or committed.

## Sharing boundary

Never stage or commit the active discovery prompt, target metadata, evidence, observations, findings, `llm-log.md`, PoCs, controls, corpora, dumps, vendor binaries or documents, IDA databases, credentials, session material, or machine-specific paths. Agent-written target scripts remain local unless they become target-independent, receive tests, and are deliberately promoted to the core.

Runtime guarantees and verification boundaries are documented in
[`research/tools/closed_source_context/CONTRACT.md`](research/tools/closed_source_context/CONTRACT.md).
