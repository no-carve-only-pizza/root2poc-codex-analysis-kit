"""Narrow discovery-only guard against crash-only completion claims."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .compactor import (
    analysis_session_active,
    completion_floor_from_prompt,
    text_claims_rce_proof,
)
from .store import read_events, run_directory

PREMATURE_COMPLETION_REASON = (
    "The active closed-source discovery objective requires reproducible attacker-controlled code execution. "
    "The last answer declared completion without explicit RCE proof. Treat crashes, denial of service, "
    "null dereferences, and read/write/UAF primitives as intermediate results; continue the most promising "
    "native path while preserving claim and evidence boundaries. If the user explicitly stopped or new "
    "authority is required, report that boundary instead."
)

_NON_COMPLETION = re.compile(
    r"(?i)(?:\bnot\s+(?:yet\s+)?(?:complete|completed|successful)\b|"
    r"\b(?:incomplete|unsuccessful)\b|미완료|"
    r"(?:완료|성공)(?:가|한\s*(?:것|게)(?:이|은)?)?\s*(?:아니|아님)|"
    r"(?:완료|성공)(?:하지|되지)\s*(?:않|못)|"
    r"완료로\s*(?:볼|처리할)\s*수\s*없)"
)
_EXPLICIT_COMPLETION_STATUS = re.compile(
    r"(?im)^\s*(?:status|result|conclusion|상태|결론)\s*[:：]\s*"
    r"(?:complete|completed|success|완료|성공)\b"
)
_COMPLETION_CLAIM = re.compile(
    r"(?im)(?:\b(?:discovery|analysis|task)\s+(?:is\s+)?(?:complete|completed|successful)\b|"
    r"(?:전체\s*)?(?:분석|탐색|작업|취약점 발견)(?:이|은|을|를)?\s*(?:완료|성공)(?:했|되|$)|"
    r"(?:취약점|vulnerability).{0,30}(?:찾았습니다|발견했습니다|was found))"
)
_USER_STOP = re.compile(
    r"(?i)^\s*(?:(?:no|아니야|됐어|오케이|okay|ok)[,\s.!]*)?"
    r"(?:stop(?: now)?|pause|cancel|그만(?:하자|해|할게)?|중단(?:해|하자)?|멈춰|여기까지)(?:\s|[.!?]|$)"
)


def _latest_user_prompt(events: list[dict[str, Any]]) -> str:
    for event in reversed(events):
        if (
            event.get("type") == "user_prompt"
            and event.get("prompt_origin", "user") != "completion_guard"
        ):
            value = event.get("prompt")
            return value if isinstance(value, str) else ""
    return ""


def _line_containing(text: str, match: re.Match[str]) -> str:
    start = text.rfind("\n", 0, match.start()) + 1
    end = text.find("\n", match.end())
    return text[start:] if end < 0 else text[start:end]


def _declares_completion(message: str) -> bool:
    # An explicit positive status wins over a contradictory disclaimer elsewhere,
    # but a locally negated status is not a completion declaration.
    for match in _EXPLICIT_COMPLETION_STATUS.finditer(message):
        if not _NON_COMPLETION.search(_line_containing(message, match)):
            return True

    # A clear overall non-completion statement suppresses weaker phrases such as
    # "a vulnerability was found" that may only describe intermediate progress.
    if _NON_COMPLETION.search(message):
        return False
    return _COMPLETION_CLAIM.search(message) is not None


def should_continue_after_stop(
    project_root: Path,
    session_id: Any,
    last_assistant_message: Any,
    stop_hook_active: Any,
) -> bool:
    if stop_hook_active is True:
        return False
    message = last_assistant_message if isinstance(last_assistant_message, str) else ""
    if not message:
        return False

    events = read_events(run_directory(project_root, session_id))
    if not analysis_session_active(events):
        return False
    if completion_floor_from_prompt(project_root) != "RCE_REQUIRED":
        return False
    if _USER_STOP.search(_latest_user_prompt(events)):
        return False
    if not _declares_completion(message):
        return False
    return not text_claims_rce_proof(message)
