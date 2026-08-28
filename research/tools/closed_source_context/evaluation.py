"""Deterministic A/B/C/D recovery-fidelity smoke evaluation.

This module checks arm construction and post-compaction state retention. It does
not call a model and therefore does not measure vulnerability-discovery lift.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

from .compactor import checkpoint_before_compaction, render_recovery_context
from .store import read_events, record_event, run_directory

EVALUATION_SCHEMA_VERSION = 1
EVALUATION_SESSION_ID = "recovery-eval"

MARKERS = {
    "objective": "EVAL-OBJECTIVE-7F3A",
    "current_hypothesis": "EVAL-HYPOTHESIS-V2-31B8",
    "confirmed_native_fact": "EVAL-CONFIRMED-F1-6A20",
    "refuted_hypothesis": "EVAL-HYPOTHESIS-V1-29C4",
    "tentative_unknown": "EVAL-UNKNOWN-U1-911D",
    "methodology": "EVAL-METHOD-M1-84D2",
    "relationship": "EVAL-RELATION-R1-508E",
    "runtime_state": "EVAL-RUNTIME-S1-1C77",
    "next_test": "EVAL-NEXT-N2-4E21",
    "canonical_evidence": (
        "research/active/closed-source-rce/eval/evidence/EVAL-EVIDENCE-3D0C.log"
    ),
    "first_tool": "EVAL-TOOL-FIRST-9AA1",
    "second_tool": "EVAL-TOOL-SECOND-2BB2",
    "exact_session": "EVAL-SESSION-5CC3",
    "primitive_boundary": "EVAL-PRIMITIVE-NULL-7EE4",
    "completion_status": "RCE_NOT_PROVEN_IN_DERIVED_STATE",
}

ARM_COMPONENTS = {
    "A": ["target_prompt"],
    "B": ["target_prompt", "project_agents", "cdb_skill"],
    "C": [
        "target_prompt",
        "project_agents",
        "cdb_skill",
        "latest_message_baseline",
    ],
    "D": [
        "target_prompt",
        "project_agents",
        "cdb_skill",
        "paper_adapted_v2_recovery",
    ],
}

EXPECTED_RECALL = {
    "A": set(),
    "B": set(),
    "C": {
        "objective",
        "current_hypothesis",
        "refuted_hypothesis",
        "next_test",
        "second_tool",
        "exact_session",
        "primitive_boundary",
        "completion_status",
    },
    "D": set(MARKERS),
}


def _write_fixture_prompt(project_root: Path) -> None:
    prompt_path = project_root / "research/active/closed-source-rce/DISCOVERY-PROMPT.md"
    prompt_path.parent.mkdir(parents=True, exist_ok=True)
    prompt_path.write_text(
        "# EvaluationTarget native vulnerability discovery prompt\n\n"
        "TARGET_PRODUCT: EvaluationTarget\n"
        "EXACT_BUILD: synthetic-build\n"
        "ARCHITECTURE: x86\n"
        "INPUT_SCOPE: synthetic-format\n"
        "MODULE: EvaluationTarget.exe\n\n"
        "RCE is the minimum success condition.\n",
        encoding="utf-8",
    )


def _record_fixture(project_root: Path, session_id: str) -> None:
    events = [
        {
            "event_id": "eval-prompt",
            "type": "user_prompt",
            "prompt_origin": "user",
            "prompt": f"Objective: {MARKERS['objective']}",
        },
        {
            "event_id": "eval-assistant-early",
            "type": "assistant_stop",
            "assistant_summary": (
                f"Hypothesis: {MARKERS['refuted_hypothesis']}\n"
                f"Confirmed: {MARKERS['confirmed_native_fact']}\n"
                f"Unknown: {MARKERS['tentative_unknown']}\n"
                f"Methodology: {MARKERS['methodology']}\n"
                f"Relationship: {MARKERS['relationship']}\n"
                f"Runtime state: {MARKERS['runtime_state']}\n"
                "Next test: EVAL-NEXT-N1-OLD"
            ),
        },
        {
            "event_id": "eval-tool-first",
            "type": "tool_result",
            "tool_family": "ida",
            "tool_name": "mcp__idalib__decompile",
            "request_summary": (
                f"{MARKERS['first_tool']} database={MARKERS['exact_session']}"
            ),
            "response_summary": (
                f"Confirmed: {MARKERS['confirmed_native_fact']} "
                f"at {MARKERS['canonical_evidence']}"
            ),
        },
        {
            "event_id": "eval-assistant-latest",
            "type": "assistant_stop",
            "assistant_summary": (
                f"Hypothesis: {MARKERS['current_hypothesis']}\n"
                f"Refuted: {MARKERS['refuted_hypothesis']}\n"
                f"Primitive: {MARKERS['primitive_boundary']}\n"
                "RCE: not proven\n"
                f"Next test: {MARKERS['next_test']}\n"
                f"completion_status: {MARKERS['completion_status']}"
            ),
        },
        {
            "event_id": "eval-tool-second",
            "type": "tool_result",
            "tool_family": "ida",
            "tool_name": "mcp__idalib__server_health",
            "request_summary": (
                f"{MARKERS['second_tool']} database={MARKERS['exact_session']}"
            ),
            "response_summary": "status=ok",
        },
    ]
    for index, event in enumerate(events):
        event["timestamp_utc"] = f"2026-08-27T00:00:{index:02d}Z"
        record_event(project_root, session_id, event)


def _latest_event_text(events: list[dict[str, Any]], event_type: str) -> str:
    for event in reversed(events):
        if event.get("type") != event_type:
            continue
        for key in ("prompt", "assistant_summary"):
            value = event.get(key)
            if isinstance(value, str):
                return value
    return ""


def render_latest_message_baseline(project_root: Path, session_id: str) -> str:
    """Render the deliberately narrow pre-v2 latest-message baseline."""

    events = read_events(run_directory(project_root, session_id))
    latest_tool = next(
        (event for event in reversed(events) if event.get("type") == "tool_result"),
        {},
    )
    lines = [
        "LATEST-MESSAGE RECOVERY BASELINE",
        _latest_event_text(events, "user_prompt"),
        _latest_event_text(events, "assistant_stop"),
        str(latest_tool.get("request_summary", "")),
        str(latest_tool.get("response_summary", "")),
    ]
    return "\n".join(line for line in lines if line)


def build_arm_contexts(project_root: Path, session_id: str) -> dict[str, str]:
    checkpoint_before_compaction(project_root, session_id, "test")
    return {
        "A": "",
        "B": "",
        "C": render_latest_message_baseline(project_root, session_id),
        "D": render_recovery_context(project_root, session_id),
    }


def _score_context(context: str) -> dict[str, Any]:
    recalled = sorted(name for name, marker in MARKERS.items() if marker in context)
    missing = sorted(set(MARKERS) - set(recalled))
    encoded = context.encode("utf-8")
    return {
        "recalled": recalled,
        "missing": missing,
        "recall_count": len(recalled),
        "recall_total": len(MARKERS),
        "recovery_chars": len(context),
        "recovery_bytes": len(encoded),
        "recovery_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def run_smoke_evaluation() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as temporary:
        project_root = Path(temporary)
        _write_fixture_prompt(project_root)
        _record_fixture(project_root, EVALUATION_SESSION_ID)
        contexts = build_arm_contexts(project_root, EVALUATION_SESSION_ID)
        arms: dict[str, dict[str, Any]] = {}
        mismatches: dict[str, dict[str, list[str]]] = {}
        for arm, context in contexts.items():
            score = _score_context(context)
            score["components"] = ARM_COMPONENTS[arm]
            arms[arm] = score
            actual = set(score["recalled"])
            expected = EXPECTED_RECALL[arm]
            if actual != expected:
                mismatches[arm] = {
                    "unexpected": sorted(actual - expected),
                    "absent": sorted(expected - actual),
                }

        return {
            "schema_version": EVALUATION_SCHEMA_VERSION,
            "evaluation_type": "deterministic_recovery_fidelity_smoke",
            "model_calls": 0,
            "same_fixture": True,
            "verdict": "PASS" if not mismatches else "FAIL",
            "arms": arms,
            "mismatches": mismatches,
            "limitation": (
                "This validates recovery-arm construction and exact marker retention; "
                "it does not measure model behavior or vulnerability-analysis lift."
            ),
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the deterministic A/B/C/D recovery-fidelity smoke evaluation."
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON.")
    args = parser.parse_args()
    report = run_smoke_evaluation()
    print(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2 if args.pretty else None,
            sort_keys=True,
            separators=None if args.pretty else (",", ":"),
        )
    )
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
