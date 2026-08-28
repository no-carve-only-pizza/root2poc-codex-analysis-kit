from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from research.tools.closed_source_context import hook
from research.tools.closed_source_context.adapters import codex
from research.tools.closed_source_context.store import run_directory, state_root


class AdapterTests(unittest.TestCase):
    def test_tool_allowlist(self) -> None:
        self.assertTrue(
            codex.should_capture_tool(
                {"tool_name": "mcp__idalib__decompile", "tool_input": {}}
            )
        )
        self.assertTrue(
            codex.should_capture_tool(
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": 'cdb.exe -hd target.exe -c "g"'},
                }
            )
        )
        self.assertTrue(
            codex.should_capture_tool(
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "gflags.exe /p /enable target.exe /full"},
                }
            )
        )
        self.assertFalse(
            codex.should_capture_tool(
                {"tool_name": "Bash", "tool_input": {"command": "rg --files research"}}
            )
        )
        self.assertFalse(
            codex.should_capture_tool(
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "rg -n CDB docs research"},
                }
            )
        )
        self.assertFalse(
            codex.should_capture_tool({"tool_name": "apply_patch", "tool_input": {}})
        )

    def test_invalid_or_oversized_payload_is_rejected(self) -> None:
        with self.assertRaises(codex.HookInputError):
            codex.parse_payload(b"[]")
        with self.assertRaises(codex.HookInputError):
            codex.parse_payload(b"{" + b"A" * codex.MAX_HOOK_INPUT_BYTES)


class HookFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.project_root = Path(self.temporary.name)
        prompt = (
            self.project_root / "research/active/closed-source-rce/DISCOVERY-PROMPT.md"
        )
        prompt.parent.mkdir(parents=True)
        prompt.write_text(
            "# TestTarget native vulnerability discovery prompt\n\n"
            "RCE is the minimum success condition.\n",
            encoding="utf-8",
        )
        self.patch = mock.patch.object(hook, "PROJECT_ROOT", self.project_root)
        self.patch.start()

    def tearDown(self) -> None:
        self.patch.stop()
        self.temporary.cleanup()

    def payload(self, event: str, **values: object) -> dict[str, object]:
        base: dict[str, object] = {
            "session_id": "thr-test",
            "turn_id": "turn-test",
            "cwd": str(self.project_root),
            "hook_event_name": event,
            "model": "test-model",
            "permission_mode": "default",
        }
        base.update(values)
        return base

    def test_generic_bash_is_not_persisted(self) -> None:
        hook.handle(
            self.payload(
                "PostToolUse",
                tool_name="Bash",
                tool_use_id="tool-generic",
                tool_input={"command": "ls -la"},
                tool_response={"output": "ordinary output"},
            )
        )
        self.assertFalse(state_root(self.project_root).exists())

    def test_compaction_reinjects_capsule_and_recent_pair(self) -> None:
        hook.handle(
            self.payload(
                "UserPromptSubmit",
                prompt="Hypothesis: route timing controls importer reachability",
            )
        )
        hook.handle(
            self.payload(
                "PostToolUse",
                tool_name="mcp__idalib__decompile",
                tool_use_id="tool-ida",
                tool_input={"session_id": "exact-idb", "address": "0x401000"},
                tool_response={"output": "Confirmed: consumer dereferences host+0x10"},
            )
        )
        hook.handle(
            self.payload(
                "Stop",
                last_assistant_message=(
                    "Confirmed: importer is reached after handoff\n"
                    "Refuted: debug heap caused the miss\n"
                    "Unknown: attacker-controlled primitive\n"
                    "Next test: preserve handoff and toggle one heap variable"
                ),
            )
        )
        hook.handle(self.payload("PreCompact", trigger="manual"))
        output = hook.handle(self.payload("SessionStart", source="compact"))
        context = output["hookSpecificOutput"]["additionalContext"]
        self.assertIn("derived state, not evidence", context)
        self.assertIn("Completion floor: RCE_REQUIRED", context)
        self.assertIn("debug heap caused the miss", context)
        self.assertIn("mcp__idalib__decompile", context)
        run_dir = run_directory(self.project_root, "thr-test")
        self.assertTrue((run_dir / "capsule.yaml").exists())
        self.assertTrue((run_dir / "recent-tools.jsonl").exists())
        for line in (
            (run_dir / "checkpoint.jsonl").read_text(encoding="utf-8").splitlines()
        ):
            json.loads(line)

    def test_compaction_does_not_inject_without_an_ida_or_cdb_result(self) -> None:
        hook.handle(self.payload("UserPromptSubmit", prompt="Update the documentation"))
        hook.handle(
            self.payload("Stop", last_assistant_message="The documentation is updated.")
        )
        hook.handle(self.payload("PreCompact", trigger="manual"))
        output = hook.handle(self.payload("SessionStart", source="compact"))
        self.assertEqual(output, {})
        run_dir = run_directory(self.project_root, "thr-test")
        self.assertFalse((run_dir / "capsule.yaml").exists())

    def test_crash_only_completion_claim_is_continued_once(self) -> None:
        hook.handle(
            self.payload(
                "PostToolUse",
                tool_name="mcp__idalib__decompile",
                tool_use_id="tool-ida",
                tool_input={"address": "0x401000"},
                tool_response={"output": "a null dereference is reachable"},
            )
        )
        message = (
            "Status: COMPLETE\nA reproducible crash and null dereference were found."
        )
        first = hook.handle(self.payload("Stop", last_assistant_message=message))
        self.assertEqual(first["decision"], "block")
        self.assertIn(
            "requires reproducible attacker-controlled code execution", first["reason"]
        )

        repeated = hook.handle(
            self.payload("Stop", last_assistant_message=message, stop_hook_active=True)
        )
        self.assertEqual(repeated, {})

        negated_rce = hook.handle(
            self.payload(
                "Stop",
                last_assistant_message="Status: COMPLETE\nRCE was not proven; only a crash was reproduced.",
            )
        )
        self.assertEqual(negated_rce["decision"], "block")

    def test_rce_proof_or_explicit_user_stop_is_not_continued(self) -> None:
        hook.handle(
            self.payload(
                "PostToolUse",
                tool_name="mcp__idalib__decompile",
                tool_use_id="tool-ida",
                tool_input={"address": "0x401000"},
                tool_response={"output": "candidate consumer"},
            )
        )
        proven = hook.handle(
            self.payload(
                "Stop",
                last_assistant_message=(
                    "Status: COMPLETE\nRCE was proven with reproducible attacker-controlled code execution."
                ),
            )
        )
        self.assertEqual(proven, {})

        hook.handle(self.payload("UserPromptSubmit", prompt="아니야 그만하자"))
        stopped = hook.handle(
            self.payload(
                "Stop",
                last_assistant_message="Status: COMPLETE\nOnly a crash was found.",
            )
        )
        self.assertEqual(stopped, {})

        prompt = (
            self.project_root / "research/active/closed-source-rce/DISCOVERY-PROMPT.md"
        )
        prompt.write_text(
            "# A target whose active prompt does not require RCE\n", encoding="utf-8"
        )
        hook.handle(self.payload("UserPromptSubmit", prompt="Continue target work"))
        prompt_defined = hook.handle(
            self.payload(
                "Stop",
                last_assistant_message="Status: COMPLETE\nOnly a crash was found.",
            )
        )
        self.assertEqual(prompt_defined, {})

    def test_bounded_experiment_completion_is_not_overread_as_task_completion(
        self,
    ) -> None:
        hook.handle(
            self.payload(
                "PostToolUse",
                tool_name="mcp__idalib__decompile",
                tool_use_id="tool-ida",
                tool_input={"address": "0x401000"},
                tool_response={"output": "candidate consumer"},
            )
        )
        output = hook.handle(
            self.payload(
                "Stop",
                last_assistant_message=(
                    "The matched CDB experiment is complete. RCE is not proven, so the next test is route comparison."
                ),
            )
        )
        self.assertEqual(output, {})

    def test_explicit_overall_noncompletion_is_not_blocked(self) -> None:
        hook.handle(
            self.payload(
                "PostToolUse",
                tool_name="mcp__idalib__decompile",
                tool_use_id="tool-ida",
                tool_input={"address": "0x401000"},
                tool_response={"output": "candidate consumer"},
            )
        )

        for message in (
            "RCE_NOT_PROVEN_IN_DERIVED_STATE이며 전체 취약점 탐색은 완료되지 않았다.",
            "전체 분석은 아직 완료되지 않았습니다.",
            "현재 결과는 중간 단계이고 전체 작업은 완료가 아닙니다.",
        ):
            with self.subTest(message=message):
                output = hook.handle(
                    self.payload("Stop", last_assistant_message=message)
                )
                self.assertEqual(output, {})

        contradictory = hook.handle(
            self.payload(
                "Stop",
                last_assistant_message=(
                    "Status: COMPLETE\n"
                    "RCE is not proven and the overall discovery is incomplete."
                ),
            )
        )
        self.assertEqual(contradictory["decision"], "block")

    def test_event_id_makes_repeated_tool_hook_idempotent(self) -> None:
        payload = self.payload(
            "PostToolUse",
            tool_name="Bash",
            tool_use_id="tool-cdb",
            tool_input={"command": "cdb.exe -p 1234"},
            tool_response={"output": "breakpoint"},
        )
        hook.handle(payload)
        hook.handle(payload)
        checkpoint = run_directory(self.project_root, "thr-test") / "checkpoint.jsonl"
        self.assertEqual(len(checkpoint.read_text(encoding="utf-8").splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
