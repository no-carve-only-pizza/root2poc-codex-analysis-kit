"""Paper-adapted checkpoint, trajectory capsule, and compact-session recovery."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .store import (
    atomic_write_text,
    file_lock,
    read_events,
    relative_pointer,
    run_directory,
    utc_now,
)

CAPSULE_SCHEMA_VERSION = 2
MAX_CAPSULE_ITEM_CHARS = 420
MAX_RECOVERY_CONTEXT_CHARS = 4_800
MAX_RECOVERY_CONTEXT_BYTES = 6_000
MAX_RECENT_TOOL_EVENTS = 2
MAX_SOURCE_EVENT_IDS = 16

_LABEL_PATTERNS: dict[str, re.Pattern[str]] = {
    "hypothesis": re.compile(
        r"(?i)^\s*(?:current[ _-]?hypothesis|hypothesis|가설)\s*[:：-]\s*(.+)$"
    ),
    "confirmed": re.compile(
        r"(?i)^\s*(?:confirmed(?: native facts?)?|supports?|확인(?:됨)?|지지)\s*[:：-]\s*(.+)$"
    ),
    "refuted": re.compile(r"(?i)^\s*(?:refuted|반증|기각)\s*[:：-]\s*(.+)$"),
    "unknown": re.compile(
        r"(?i)^\s*(?:tentative|unknown|remains[ _-]?unknown|추정|미확인|불명)\s*[:：-]\s*(.+)$"
    ),
    "next": re.compile(
        r"(?i)^\s*(?:next(?: discriminating)? test|next question|다음(?: 구분)? 실험|다음 질문)\s*[:：-]\s*(.+)$"
    ),
    "methodology": re.compile(
        r"(?i)^\s*(?:methodology|method|analysis method|방법|분석 방법)\s*[:：-]\s*(.+)$"
    ),
    "relationship": re.compile(
        r"(?i)^\s*(?:cross[ _-]?function relationship|relationship|관계|함수 간 관계)\s*[:：-]\s*(.+)$"
    ),
    "runtime_state": re.compile(
        r"(?i)^\s*(?:runtime state|external state|product state|실행 상태|외부 상태|제품 상태)\s*[:：-]\s*(.+)$"
    ),
    "work_state": re.compile(
        r"(?i)^\s*(?:current work state|work state|current state|작업 상태|현재 상태)\s*[:：-]\s*(.+)$"
    ),
}

_CLAIM_PATTERNS: dict[str, re.Pattern[str]] = {
    "reachability": re.compile(r"(?i)^\s*(?:reachability|도달성)\s*[:：-]\s*(.+)$"),
    "trigger": re.compile(
        r"(?i)^\s*(?:trigger(?:/crash)?|트리거|크래시)\s*[:：-]\s*(.+)$"
    ),
    "primitive": re.compile(r"(?i)^\s*(?:native )?primitive\s*[:：-]\s*(.+)$"),
    "file_control": re.compile(r"(?i)^\s*(?:file control|파일 제어)\s*[:：-]\s*(.+)$"),
    "exploitability": re.compile(
        r"(?i)^\s*(?:exploitability(?: boundary)?|악용 가능성)\s*[:：-]\s*(.+)$"
    ),
    "rce": re.compile(
        r"(?i)^\s*(?:rce(?: boundary)?|code execution|코드 실행)\s*[:：-]\s*(.+)$"
    ),
    "novelty": re.compile(r"(?i)^\s*(?:novelty|신규성)\s*[:：-]\s*(.+)$"),
    "reportability": re.compile(
        r"(?i)^\s*(?:reportability|disclosure boundary|제보 가능성)\s*[:：-]\s*(.+)$"
    ),
}

_TARGET_FIELD = re.compile(
    r"(?im)^\s*(TARGET_PRODUCT|EXACT_BUILD|ARCHITECTURE|INPUT_SCOPE|MODULE)\s*:\s*(.+?)\s*$"
)
_EVIDENCE_PATH = re.compile(
    r"(?<![A-Za-z0-9_.-])((?:research/)?[A-Za-z0-9_./-]*(?:evidence|observation|findings)/[A-Za-z0-9_./-]+)"
)
_RCE_TERM = re.compile(
    r"(?i)(?:\brce\b|attacker[- ]controlled code execution|공격자 제어 코드 실행|코드 실행)"
)
_RCE_NEGATIVE = re.compile(
    r"(?i)(?:not\s+(?:proven|confirmed|reproduced|achieved|demonstrated|shown|established|reached|ruled out)|"
    r"\b(?:unproven|unconfirmed|unreproduced|unsupported|undetermined|unknown|unreachable|failed|failure|false)\b|"
    r"\b(?:no|without)\s+(?:proof|evidence|confirmation|reproduction|demonstration)\b|"
    r"\b(?:possible|potential|candidate|hypothesis|under analysis)\b|"
    r"미입증|입증되지|확인되지|재현되지|성공하지|실패|아님|없음|없다|불가|못함|불명|미확인)"
)
_RCE_PROOF = re.compile(
    r"(?ix)(?:"
    r"(?:\brce\b|attacker[- ]controlled\s+code\s+execution)"
    r"\s*(?:(?:is|was|has\s+been)\s+|[:=\-]\s*)"
    r"(?:proven|confirmed|reproduced|achieved|demonstrated)\b|"
    r"(?:proven|confirmed|reproduced|achieved|demonstrated)\s+"
    r"(?:an?\s+)?(?:\brce\b|attacker[- ]controlled\s+code\s+execution)|"
    r"(?:공격자\s*제어\s*코드\s*실행|코드\s*실행)(?:을|를|이|가|은|는)?\s*"
    r"(?:입증|확인|재현|달성|성공)|"
    r"(?:입증된|확인된|재현된|달성된)\s*(?:공격자\s*제어\s*코드\s*실행|코드\s*실행)"
    r")"
)


def _bounded(text: str, limit: int = MAX_CAPSULE_ITEM_CHARS) -> str:
    compact = re.sub(r"\s+", " ", text).strip()
    if len(compact) <= limit:
        return compact
    return compact[: limit - 16].rstrip() + " ...[bounded]"


def text_claims_rce_proof(text: str) -> bool:
    """Accept only an explicit positive RCE line, never a negated mention."""

    for line in text.splitlines():
        if not _RCE_TERM.search(line) or _RCE_NEGATIVE.search(line):
            continue
        if _RCE_PROOF.search(line):
            return True
    return False


def _event_texts(event: dict[str, Any]) -> list[str]:
    event_type = event.get("type")
    if event_type == "user_prompt":
        keys = ("prompt",)
    elif event_type == "assistant_stop":
        keys = ("assistant_summary",)
    elif event_type == "tool_result":
        keys = ("request_summary", "response_summary")
    else:
        keys = ("prompt", "assistant_summary", "request_summary", "response_summary")
    values: list[str] = []
    for key in keys:
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value)
    return values


def _event_text(event: dict[str, Any]) -> str:
    return "\n".join(_event_texts(event))


def _latest(events: Iterable[dict[str, Any]], event_type: str) -> dict[str, Any] | None:
    result = None
    for event in events:
        if event.get("type") == event_type:
            result = event
    return result


def _latest_user_objective(
    events: Iterable[dict[str, Any]],
) -> dict[str, Any] | None:
    """Prefer a real user prompt over a Stop-hook continuation prompt."""

    latest_prompt = None
    latest_user_prompt = None
    for event in events:
        if event.get("type") != "user_prompt":
            continue
        latest_prompt = event
        if event.get("prompt_origin", "user") != "completion_guard":
            latest_user_prompt = event
    return latest_user_prompt or latest_prompt


def _is_relevant_tool_event(event: dict[str, Any]) -> bool:
    return event.get("type") == "tool_result" and event.get("tool_family") in {
        "ida",
        "cdb",
    }


def _tool_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [event for event in events if _is_relevant_tool_event(event)]


def analysis_session_active(events: Iterable[dict[str, Any]]) -> bool:
    """Activate recovery only after an allowlisted IDA/CDB result was captured."""

    return any(_is_relevant_tool_event(event) for event in events)


def completion_floor_from_prompt(project_root: Path) -> str:
    prompt_path = project_root / "research/active/closed-source-rce/DISCOVERY-PROMPT.md"
    if not prompt_path.exists():
        return "PROMPT_DEFINED"
    text = prompt_path.read_text(encoding="utf-8", errors="replace")
    if "RCE is the minimum success condition" in text:
        return "RCE_REQUIRED"
    return "PROMPT_DEFINED"


def _extract_labeled(text: str, label: str) -> list[str]:
    pattern = _LABEL_PATTERNS[label]
    values: list[str] = []
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            value = _bounded(match.group(1))
            if value:
                values.append(value)
    return values


def _collect_labeled(
    events: Iterable[dict[str, Any]], label: str, limit: int = 5
) -> list[str]:
    values: list[str] = []
    for event in events:
        for text in _event_texts(event):
            for value in _extract_labeled(text, label):
                if value in values:
                    values.remove(value)
                values.append(value)
    return values[-limit:]


def _claim_key(value: str) -> str:
    return re.sub(r"[^a-z0-9가-힣]+", " ", value.lower()).strip()


def _resolved_claims(events: Iterable[dict[str, Any]]) -> dict[str, list[str]]:
    """Resolve exact repeated claims by their latest explicit status."""

    states: dict[str, tuple[str, str, int]] = {}
    order = 0
    for event in events:
        for text in _event_texts(event):
            for label in ("confirmed", "refuted", "unknown"):
                for value in _extract_labeled(text, label):
                    order += 1
                    states[_claim_key(value)] = (label, value, order)
    result = {"confirmed": [], "refuted": [], "unknown": []}
    for label, value, _ in sorted(states.values(), key=lambda item: item[2]):
        result[label].append(value)
    for label in result:
        result[label] = result[label][-5:]
    return result


def _latest_claim_boundaries(events: Iterable[dict[str, Any]]) -> dict[str, str]:
    boundaries: dict[str, str] = {}
    for event in events:
        for text in _event_texts(event):
            for line in text.splitlines():
                for name, pattern in _CLAIM_PATTERNS.items():
                    match = pattern.match(line)
                    if match:
                        boundaries[name] = _bounded(match.group(1))
    return boundaries


def _active_target_hint(project_root: Path, events: Iterable[dict[str, Any]]) -> str:
    fields: dict[str, str] = {}
    for event in events:
        for text in _event_texts(event):
            fields.update(
                {key: value.strip() for key, value in _TARGET_FIELD.findall(text)}
            )
    if fields:
        return _bounded(" / ".join(f"{key}={value}" for key, value in fields.items()))

    prompt_path = project_root / "research/active/closed-source-rce/DISCOVERY-PROMPT.md"
    if not prompt_path.exists():
        return "Active discovery prompt unavailable"
    text = prompt_path.read_text(encoding="utf-8", errors="replace")[:8_000]
    prompt_fields = {key: value.strip() for key, value in _TARGET_FIELD.findall(text)}
    if prompt_fields:
        return _bounded(
            " / ".join(f"{key}={value}" for key, value in prompt_fields.items())
        )
    for line in text.splitlines():
        if line.startswith("# "):
            return _bounded(
                f"{line[2:].strip()} / verify exact build and route from canonical evidence"
            )
    return "See active discovery prompt and canonical target evidence"


def _canonical_evidence_pointer(project_root: Path, value: str) -> str | None:
    """Normalize a canonical pointer and reject traversal or derived-state paths."""

    candidate = Path(value)
    if ".." in candidate.parts or ".agent-state" in candidate.parts:
        return None
    root = project_root.resolve()
    resolved = (
        candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
    )
    try:
        relative = resolved.relative_to(root)
    except ValueError:
        return None
    if not {"evidence", "observation", "findings"}.intersection(relative.parts):
        return None
    return relative.as_posix()


def _evidence_pointers(
    project_root: Path, events: Iterable[dict[str, Any]], limit: int = 8
) -> list[str]:
    pointers: list[str] = []
    for event in events:
        for text in _event_texts(event):
            for match in _EVIDENCE_PATH.finditer(text):
                value = _canonical_evidence_pointer(
                    project_root, match.group(1).rstrip(".,:;)")
                )
                if value and value not in pointers:
                    pointers.append(value)
    return pointers[-limit:]


def _derived_capture_pointers(
    events: Iterable[dict[str, Any]], limit: int = 8
) -> list[str]:
    pointers: list[str] = []
    for event in events:
        for capture_key in ("request_capture", "response_capture", "message_capture"):
            capture = event.get(capture_key)
            if isinstance(capture, dict):
                ref = capture.get("ref")
                if isinstance(ref, str) and ref and ref not in pointers:
                    pointers.append(ref)
    return pointers[-limit:]


def _checkpoint_metadata(project_root: Path, run_dir: Path) -> tuple[str, str]:
    checkpoint_path = run_dir / "checkpoint.jsonl"
    if not checkpoint_path.exists():
        return "", ""
    with file_lock(checkpoint_path):
        checkpoint_bytes = checkpoint_path.read_bytes()
    return (
        relative_pointer(project_root, checkpoint_path),
        hashlib.sha256(checkpoint_bytes).hexdigest(),
    )


def _normalized_trigger(trigger: str) -> str:
    return trigger if trigger in {"manual", "auto", "test"} else "unknown"


def build_capsule(project_root: Path, session_id: Any, trigger: str) -> dict[str, Any]:
    run_dir = run_directory(project_root, session_id)
    events = read_events(run_dir)
    prompt_event = _latest_user_objective(events) or {}
    assistant_event = _latest(events, "assistant_stop") or {}
    tool_events = _tool_events(events)
    latest_tool = tool_events[-1] if tool_events else {}
    active = analysis_session_active(events)

    hypotheses = _collect_labeled(events, "hypothesis", limit=1)
    claims = _resolved_claims(events)
    next_tests = _collect_labeled(events, "next", limit=1)
    methodology = _collect_labeled(events, "methodology", limit=3)
    relationships = _collect_labeled(events, "relationship", limit=5)
    runtime_state = _collect_labeled(events, "runtime_state", limit=3)
    work_states = _collect_labeled(events, "work_state", limit=1)
    boundaries = _latest_claim_boundaries(events)
    pointers = _evidence_pointers(project_root, events)
    derived_pointers = _derived_capture_pointers(events)
    checkpoint_ref, checkpoint_sha256 = _checkpoint_metadata(project_root, run_dir)

    latest_assistant_text = _event_text(assistant_event)
    rce_text = "\n".join((boundaries.get("rce", ""), latest_assistant_text))
    completion_status = (
        "RCE_CLAIM_REQUIRES_CANONICAL_REVERIFICATION"
        if text_claims_rce_proof(rce_text)
        else "RCE_NOT_PROVEN_IN_DERIVED_STATE"
    )

    response_capture = latest_tool.get("response_capture")
    last_tool_ref = (
        response_capture.get("ref", "") if isinstance(response_capture, dict) else ""
    )
    source_event_ids = [
        str(event.get("event_id", "")) for event in events if event.get("event_id")
    ][-MAX_SOURCE_EVENT_IDS:]
    recent_tool_event_ids = [
        str(event.get("event_id", ""))
        for event in tool_events[-MAX_RECENT_TOOL_EVENTS:]
        if event.get("event_id")
    ]

    objective_text = _event_text(prompt_event)
    fallback_work_state = (
        _bounded(latest_assistant_text) if latest_assistant_text else ""
    )
    return {
        "schema_version": CAPSULE_SCHEMA_VERSION,
        "case_id": str(session_id or ""),
        "generated_utc": utc_now(),
        "trigger": _normalized_trigger(trigger),
        "capture_scope": "redacted hook-visible derived state; not canonical evidence",
        "analysis_active": active,
        "activation_reason": (
            "captured_ida_or_cdb_tool_event"
            if active
            else "inactive_no_relevant_tool_event"
        ),
        "objective": (
            _bounded(objective_text)
            if objective_text
            else "Re-open the latest user objective before continuing."
        ),
        "exact_target": _active_target_hint(project_root, events),
        "completion_floor": completion_floor_from_prompt(project_root),
        "completion_status": completion_status,
        "current_hypothesis": (
            hypotheses[0]
            if hypotheses
            else "No structured hypothesis was auto-extracted."
        ),
        "work_state": (
            work_states[0]
            if work_states
            else fallback_work_state
            or "Re-open the latest canonical evidence before continuing."
        ),
        "methodology_notes": methodology,
        "cross_function_relationships": relationships,
        "runtime_state": runtime_state,
        "claim_boundaries": boundaries,
        "confirmed_native_facts": claims["confirmed"],
        "refuted_hypotheses": claims["refuted"],
        "tentative_or_unknown": claims["unknown"]
        or [
            "No explicit tentative/unknown label was auto-extracted; reverify unresolved claims from canonical evidence."
        ],
        "checkpoint_ref": checkpoint_ref,
        "checkpoint_sha256": checkpoint_sha256,
        "last_tool_result_ref": last_tool_ref,
        "last_tool_event_id": str(latest_tool.get("event_id", "")),
        "recent_tool_event_ids": recent_tool_event_ids,
        "next_discriminating_test": (
            next_tests[0]
            if next_tests
            else "Re-open the latest canonical evidence and select the next one-variable test."
        ),
        "evidence_pointers": pointers,
        "derived_capture_pointers": derived_pointers,
        "source_event_count": len(events),
        "source_event_ids": source_event_ids,
    }


def _yaml_scalar(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)


def dump_capsule_yaml(capsule: dict[str, Any]) -> str:
    list_fields = {
        "methodology_notes",
        "cross_function_relationships",
        "runtime_state",
        "confirmed_native_facts",
        "refuted_hypotheses",
        "tentative_or_unknown",
        "recent_tool_event_ids",
        "evidence_pointers",
        "derived_capture_pointers",
        "source_event_ids",
    }
    lines: list[str] = []
    for key, value in capsule.items():
        if key in list_fields:
            if not value:
                lines.append(f"{key}: []")
            else:
                lines.append(f"{key}:")
                for item in value:
                    lines.append(f"  - {_yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {_yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


def load_capsule_yaml(text: str) -> dict[str, Any]:
    """Parse only the deterministic JSON-scalar YAML emitted above."""

    result: dict[str, Any] = {}
    current_list: str | None = None
    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue
        if raw_line.startswith("  - "):
            if current_list is None:
                raise ValueError("list item without a key")
            result[current_list].append(json.loads(raw_line[4:]))
            continue
        if raw_line.startswith(" ") or ":" not in raw_line:
            raise ValueError("unsupported capsule YAML shape")
        key, raw_value = raw_line.split(":", 1)
        raw_value = raw_value.strip()
        if not raw_value:
            result[key] = []
            current_list = key
        else:
            value = json.loads(raw_value)
            result[key] = value
            current_list = key if isinstance(value, list) else None
    return result


def write_recent_tools(project_root: Path, session_id: Any) -> Path:
    run_dir = run_directory(project_root, session_id)
    tool_events = _tool_events(read_events(run_dir))[-MAX_RECENT_TOOL_EVENTS:]
    path = run_dir / "recent-tools.jsonl"
    content = "".join(
        json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
        for event in tool_events
    )
    with file_lock(path):
        atomic_write_text(path, content)
    return path


def write_recent_tool(project_root: Path, session_id: Any) -> Path:
    """Compatibility alias for the baseline API."""

    return write_recent_tools(project_root, session_id)


def checkpoint_before_compaction(
    project_root: Path, session_id: Any, trigger: str
) -> dict[str, str]:
    run_dir = run_directory(project_root, session_id)
    if not analysis_session_active(read_events(run_dir)):
        return {"active": "false", "capsule": "", "recent_tools": ""}

    capsule = build_capsule(project_root, session_id, trigger)
    capsule_path = run_dir / "capsule.yaml"
    with file_lock(capsule_path):
        atomic_write_text(capsule_path, dump_capsule_yaml(capsule))
    recent_path = write_recent_tools(project_root, session_id)
    return {
        "active": "true",
        "capsule": relative_pointer(project_root, capsule_path),
        "recent_tools": relative_pointer(project_root, recent_path),
    }


def _read_recent_tools(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            events.append(value)
    return events[-MAX_RECENT_TOOL_EVENTS:]


def _recovery_lines(capsule: dict[str, Any], recent: list[dict[str, Any]]) -> list[str]:
    completion_floor = str(capsule.get("completion_floor", "PROMPT_DEFINED"))
    completion_line = (
        "Completion floor: RCE_REQUIRED. A crash, DoS, null dereference, or read/write/UAF primitive is progress, not completion."
        if completion_floor == "RCE_REQUIRED"
        else "Completion floor: PROMPT_DEFINED. Re-open the active discovery prompt before declaring completion."
    )
    lines = [
        "CLOSED-SOURCE RECOVERY CONTRACT",
        "This is redacted derived state, not evidence. Reverify tentative claims against canonical raw evidence.",
        completion_line,
        f"completion_status: {_bounded(str(capsule.get('completion_status', '')), 180)}",
        f"objective: {_bounded(str(capsule.get('objective', '')), 420)}",
        f"exact_target: {_bounded(str(capsule.get('exact_target', '')), 360)}",
        f"current_hypothesis: {_bounded(str(capsule.get('current_hypothesis', '')), 360)}",
        f"work_state: {_bounded(str(capsule.get('work_state', '')), 360)}",
        f"next_discriminating_test: {_bounded(str(capsule.get('next_discriminating_test', '')), 360)}",
        f"checkpoint_ref: {_bounded(str(capsule.get('checkpoint_ref', '')), 260)}",
        f"checkpoint_sha256: {_bounded(str(capsule.get('checkpoint_sha256', '')), 80)}",
    ]

    boundaries = capsule.get("claim_boundaries")
    if isinstance(boundaries, dict) and boundaries:
        lines.append(
            "claim_boundaries: "
            + _bounded(json.dumps(boundaries, ensure_ascii=False, sort_keys=True), 650)
        )

    list_sections = (
        ("methodology", capsule.get("methodology_notes")),
        ("confirmed", capsule.get("confirmed_native_facts")),
        ("refuted", capsule.get("refuted_hypotheses")),
        ("tentative_or_unknown", capsule.get("tentative_or_unknown")),
        ("relationships", capsule.get("cross_function_relationships")),
        ("runtime_state", capsule.get("runtime_state")),
        ("canonical_evidence_pointer", capsule.get("evidence_pointers")),
        ("derived_capture_pointer", capsule.get("derived_capture_pointers")),
    )
    for label, values in list_sections:
        if not isinstance(values, list):
            continue
        for value in values:
            lines.append(f"{label}: {_bounded(str(value), 300)}")

    for index, event in enumerate(recent, start=1):
        request_capture = event.get("request_capture") or {}
        response_capture = event.get("response_capture") or {}
        if not isinstance(request_capture, dict):
            request_capture = {}
        if not isinstance(response_capture, dict):
            response_capture = {}
        lines.extend(
            (
                f"recent_tool_{index}: {_bounded(str(event.get('tool_name', '')), 120)}",
                f"recent_request_{index}: {_bounded(str(event.get('request_summary', '')), 260)}",
                f"recent_response_{index}: {_bounded(str(event.get('response_summary', '')), 420)}",
                f"recent_refs_{index}: {_bounded(str(request_capture.get('ref', '')), 180)} | {_bounded(str(response_capture.get('ref', '')), 180)}",
            )
        )
    return lines


def _fit_recovery_context(lines: list[str]) -> str:
    closing = "Continue from the next discriminating test. Do not infer RCE, novelty, or reportability from this capsule."
    kept: list[str] = []
    for line in lines:
        candidate = "\n".join((*kept, line, closing))
        if (
            len(candidate) > MAX_RECOVERY_CONTEXT_CHARS
            or len(candidate.encode("utf-8")) > MAX_RECOVERY_CONTEXT_BYTES
        ):
            continue
        kept.append(line)
    context = "\n".join((*kept, closing))
    return context


def render_recovery_context(project_root: Path, session_id: Any) -> str:
    run_dir = run_directory(project_root, session_id)
    if not analysis_session_active(read_events(run_dir)):
        return ""

    capsule_path = run_dir / "capsule.yaml"
    recent_path = run_dir / "recent-tools.jsonl"
    if not capsule_path.exists():
        return (
            "Closed-source recovery state was not captured for this active analysis session. "
            "Re-open the active discovery prompt and canonical OBS/evidence. RCE remains the completion floor."
        )
    try:
        capsule = load_capsule_yaml(
            capsule_path.read_text(encoding="utf-8", errors="replace")
        )
    except (ValueError, json.JSONDecodeError):
        return (
            "Closed-source recovery capsule could not be parsed. Re-open the checkpoint, active discovery prompt, "
            "and canonical evidence. Do not treat a crash or primitive as completion; RCE remains required."
        )
    if capsule.get("analysis_active") is not True:
        return ""
    return _fit_recovery_context(
        _recovery_lines(capsule, _read_recent_tools(recent_path))
    )
