# Closed-source native vulnerability discovery prompt

> Status: TEMPLATE — copy to `research/active/closed-source-rce/DISCOVERY-PROMPT.md` and replace every bracketed value

Use IDA MCP and the authorized local runtime freely to find and prove a reproducible native RCE in `[PRODUCT_OR_COMPONENT]`.

## Scope

- Product and owner: `[PRODUCT_OR_COMPONENT]`, `[PROCESS_OR_MODULE_OWNER]`
- In scope: `[AUTHORIZED_INPUT_FORMATS_AND_OWNED_CONSUMERS]`
- Out of scope: `[EXCLUDED_FORMATS_PRODUCTS_COMPONENTS_AND_OTHER_OWNERS]`
- Shared-tool ownership: `[IDA_GUI_DEBUGGER_AND_APPLICATION_OWNERSHIP_RULE]`
- Before IDA work, call `idb_list` and use only an exact session ID returned by `idb_list` or `idb_open`.

## Execution

- Deepen a promising native hypothesis toward attacker-controlled semantic effect. A bounded failed row is not lane closure: before rotating, pursue concrete size or value variants, live targets or later consumers, sibling fields, and chains that could expand the exploitability boundary. Rotate only when assembly or reproducible native evidence closes the reachable variants at that boundary, or when no concrete development hypothesis remains; do not stop with a plan or static lead.

## Completion and safety

- RCE is the minimum success condition: complete only when an exact in-scope file trigger and matched control prove a distinct root cause that reaches reproducible attacker-controlled code execution in `[PRODUCT_OR_COMPONENT]`. A crash, denial of service, null dereference, read/write/UAF primitive, or exploitability hypothesis alone is progress, not completion.
- Do not upload, disclose, contact a vendor, build a weaponized payload, cross scope, or conflict with another owner's tools or sessions without approval.
- Continue real analysis until the completion condition is met or the user stops. Start from the real files and IDA MCP now.
