"""Single entry point for the project-local Codex lifecycle hooks."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.tools.closed_source_context.adapters.codex import (
    HookInputError,
    base_event,
    bounded_summary,
    parse_payload,
    payload_is_for_project,
    should_capture_tool,
    tool_event_id,
    tool_family,
)
from research.tools.closed_source_context.compactor import (
    checkpoint_before_compaction,
    render_recovery_context,
    write_recent_tools,
)
from research.tools.closed_source_context.guard import (
    PREMATURE_COMPLETION_REASON,
    should_continue_after_stop,
)
from research.tools.closed_source_context.store import (
    record_event,
    redact_value,
    stable_id,
    write_capture,
)


def _session_id(payload: dict[str, Any]) -> str:
    value = payload.get("session_id")
    return value if isinstance(value, str) and value else "unknown-session"


def _record_user_prompt(payload: dict[str, Any]) -> None:
    prompt = payload.get("prompt", "")
    prompt_origin = (
        "completion_guard" if prompt == PREMATURE_COMPLETION_REASON else "user"
    )
    event_id = stable_id(
        _session_id(payload),
        payload.get("turn_id"),
        "user_prompt",
        redact_value(prompt),
        prefix="prompt",
    )
    capture = write_capture(
        PROJECT_ROOT, _session_id(payload), event_id, "message", prompt
    )
    event = base_event(payload, "user_prompt", event_id)
    event.update(
        {
            "prompt": bounded_summary(prompt, 4_000),
            "prompt_origin": prompt_origin,
            "message_capture": capture,
        }
    )
    record_event(PROJECT_ROOT, _session_id(payload), event)


def _record_tool_result(payload: dict[str, Any]) -> None:
    if not should_capture_tool(payload):
        return
    event_id = tool_event_id(payload)
    request = payload.get("tool_input")
    response = payload.get("tool_response")
    request_capture = write_capture(
        PROJECT_ROOT, _session_id(payload), event_id, "request", request
    )
    response_capture = write_capture(
        PROJECT_ROOT, _session_id(payload), event_id, "response", response
    )
    event = base_event(payload, "tool_result", event_id)
    family = tool_family(payload)
    event.update(
        {
            "tool_name": payload.get("tool_name", ""),
            "tool_use_id": payload.get("tool_use_id", ""),
            "tool_family": family,
            "request_summary": bounded_summary(request),
            "response_summary": bounded_summary(response),
            "request_capture": request_capture,
            "response_capture": response_capture,
            "capture_scope": (
                "hook-visible MCP call result; host or server truncation may already exist"
                if family == "ida"
                else "hook-visible model-facing Bash result; host truncation may already exist"
            ),
            "canonical_evidence": False,
        }
    )
    _, appended = record_event(PROJECT_ROOT, _session_id(payload), event)
    if appended:
        write_recent_tools(PROJECT_ROOT, _session_id(payload))


def _record_assistant_stop(payload: dict[str, Any]) -> None:
    message = payload.get("last_assistant_message") or ""
    event_id = stable_id(
        _session_id(payload),
        payload.get("turn_id"),
        "assistant_stop",
        redact_value(message),
        prefix="assistant",
    )
    capture = write_capture(
        PROJECT_ROOT, _session_id(payload), event_id, "message", message
    )
    event = base_event(payload, "assistant_stop", event_id)
    event.update(
        {
            "assistant_summary": bounded_summary(message, 5_000),
            "message_capture": capture,
        }
    )
    record_event(PROJECT_ROOT, _session_id(payload), event)


def _record_marker(payload: dict[str, Any], marker_type: str) -> None:
    trigger = payload.get("trigger", payload.get("source", ""))
    event_id = stable_id(
        _session_id(payload),
        payload.get("turn_id"),
        marker_type,
        trigger,
        prefix="lifecycle",
    )
    event = base_event(payload, marker_type, event_id)
    event["trigger"] = trigger
    record_event(PROJECT_ROOT, _session_id(payload), event)


def handle(payload: dict[str, Any]) -> dict[str, Any]:
    if not payload_is_for_project(payload, PROJECT_ROOT):
        return {}

    event_name = payload.get("hook_event_name")
    if event_name == "UserPromptSubmit":
        _record_user_prompt(payload)
        return {}
    if event_name == "PostToolUse":
        _record_tool_result(payload)
        return {}
    if event_name == "Stop":
        _record_assistant_stop(payload)
        if should_continue_after_stop(
            PROJECT_ROOT,
            _session_id(payload),
            payload.get("last_assistant_message"),
            payload.get("stop_hook_active"),
        ):
            return {"decision": "block", "reason": PREMATURE_COMPLETION_REASON}
        return {}
    if event_name == "PreCompact":
        _record_marker(payload, "pre_compact")
        checkpoint_before_compaction(
            PROJECT_ROOT, _session_id(payload), str(payload.get("trigger", "unknown"))
        )
        return {}
    if event_name == "PostCompact":
        _record_marker(payload, "post_compact")
        return {}
    if event_name == "SessionStart" and payload.get("source") == "compact":
        _record_marker(payload, "session_start_compact")
        recovery_context = render_recovery_context(PROJECT_ROOT, _session_id(payload))
        if not recovery_context:
            return {}
        return {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": recovery_context,
            }
        }
    return {}


def main() -> int:
    try:
        payload = parse_payload(sys.stdin.buffer.read())
        output = handle(payload)
    except HookInputError:
        output = {"systemMessage": "Closed-source context hook ignored invalid input."}
    # Recovery hooks must fail open without affecting canonical evidence.
    except Exception as exc:  # noqa: BLE001
        output = {
            "systemMessage": f"Closed-source context hook failed open ({type(exc).__name__}); canonical evidence is unaffected."
        }
    sys.stdout.write(
        json.dumps(output, ensure_ascii=False, separators=(",", ":")) + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
