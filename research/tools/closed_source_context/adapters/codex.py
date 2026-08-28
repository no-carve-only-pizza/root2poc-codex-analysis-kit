"""Normalize the documented Codex hook wire format without trusting it."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..store import redact_value, stable_id

MAX_HOOK_INPUT_BYTES = 12 * 1024 * 1024
IDA_TOOL_PREFIXES = ("mcp__idalib__",)
_CDB_EXECUTABLE = re.compile(
    r"(?ix)(?:^|[;&|(\n\"'])\s*(?:&\s*)?(?:(?:[A-Za-z]:)?[^\s\"';&|]*[\\/])?"
    r"(?:cdb|windbg|ntsd)(?:\.exe)?(?=$|[\s\"'])|\b(?:cdb|windbg|ntsd)\.exe\b"
)
_DEBUG_SETUP_EXECUTABLE = re.compile(r"(?i)\b(?:gflags|appverif)\.exe\b")
_CDB_SCRIPT = re.compile(
    r"(?i)(?:^|[\\/\s\"'])(?:run[-_])?cdb[-_A-Za-z0-9.]*\.(?:ps1|cmd|bat|py)\b"
)
_DEBUG_HEAP_ASSIGNMENT = re.compile(
    r"(?i)(?:^|[;&|\s])_NO_DEBUG_HEAP\s*=\s*(?:1|true)\b"
)


class HookInputError(ValueError):
    pass


def parse_payload(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_HOOK_INPUT_BYTES:
        raise HookInputError("hook input exceeds the local safety limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HookInputError("hook input is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise HookInputError("hook input must be an object")
    return value


def payload_is_for_project(payload: dict[str, Any], project_root: Path) -> bool:
    cwd_value = payload.get("cwd")
    if not isinstance(cwd_value, str) or not cwd_value:
        return False
    try:
        cwd = Path(cwd_value).resolve()
        root = project_root.resolve()
    except (OSError, RuntimeError):
        return False
    return cwd == root or root in cwd.parents


def is_ida_tool(tool_name: Any) -> bool:
    return isinstance(tool_name, str) and tool_name.startswith(IDA_TOOL_PREFIXES)


def bash_command(tool_input: Any) -> str:
    if not isinstance(tool_input, dict):
        return ""
    value = tool_input.get("command", tool_input.get("cmd", ""))
    return value if isinstance(value, str) else ""


def is_cdb_related_bash(tool_input: Any) -> bool:
    command = bash_command(tool_input)
    return any(
        pattern.search(command)
        for pattern in (
            _CDB_EXECUTABLE,
            _DEBUG_SETUP_EXECUTABLE,
            _CDB_SCRIPT,
            _DEBUG_HEAP_ASSIGNMENT,
        )
    )


def should_capture_tool(payload: dict[str, Any]) -> bool:
    tool_name = payload.get("tool_name")
    if is_ida_tool(tool_name):
        return True
    return tool_name == "Bash" and is_cdb_related_bash(payload.get("tool_input"))


def tool_family(payload: dict[str, Any]) -> str:
    return "ida" if is_ida_tool(payload.get("tool_name")) else "cdb"


def bounded_summary(value: Any, limit: int = 1800) -> str:
    sanitized = redact_value(value)
    if isinstance(sanitized, str):
        text = sanitized
    else:
        text = json.dumps(sanitized, ensure_ascii=False, sort_keys=True, default=str)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = "\n".join(re.sub(r"[ \t]+", " ", line).strip() for line in text.splitlines())
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) <= limit:
        return text
    head = limit * 2 // 3
    tail = limit - head
    return f"{text[:head]} ...[bounded]... {text[-tail:]}"


def tool_event_id(payload: dict[str, Any]) -> str:
    return stable_id(
        payload.get("session_id"),
        payload.get("turn_id"),
        payload.get("tool_use_id"),
        payload.get("tool_name"),
        prefix="tool",
    )


def base_event(
    payload: dict[str, Any], event_type: str, event_id: str
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "type": event_type,
        "hook_event_name": payload.get("hook_event_name", ""),
        "turn_id": payload.get("turn_id", ""),
        "model": payload.get("model", ""),
        "permission_mode": payload.get("permission_mode", ""),
    }
