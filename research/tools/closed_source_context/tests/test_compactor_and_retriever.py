from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from research.tools.closed_source_context.compactor import (
    CAPSULE_SCHEMA_VERSION,
    MAX_RECOVERY_CONTEXT_BYTES,
    MAX_RECOVERY_CONTEXT_CHARS,
    build_capsule,
    checkpoint_before_compaction,
    dump_capsule_yaml,
    load_capsule_yaml,
    render_recovery_context,
    text_claims_rce_proof,
)
from research.tools.closed_source_context.evaluation import (
    EXPECTED_RECALL,
    MARKERS,
    run_smoke_evaluation,
)
from research.tools.closed_source_context.retriever import (
    bm25_search,
    build_index,
    discover_cards,
)
from research.tools.closed_source_context.store import record_event


class CompactorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.project_root = Path(self.temporary.name)
        prompt = (
            self.project_root / "research/active/closed-source-rce/DISCOVERY-PROMPT.md"
        )
        prompt.parent.mkdir(parents=True)
        prompt.write_text(
            "# ExampleProduct native vulnerability discovery prompt\n\n"
            "RCE is the minimum success condition.\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_capsule_round_trip_preserves_claim_labels(self) -> None:
        record_event(
            self.project_root,
            "capsule-session",
            {
                "event_id": "prompt",
                "type": "user_prompt",
                "prompt": "Hypothesis: object lifetime crosses cleanup",
            },
        )
        record_event(
            self.project_root,
            "capsule-session",
            {
                "event_id": "tool",
                "type": "tool_result",
                "tool_family": "ida",
                "tool_name": "mcp__idalib__xrefs",
                "request_summary": "xrefs for consumer",
                "response_summary": "Confirmed: exact consumer exists",
                "response_capture": {"ref": "research/.agent-state/example.json"},
            },
        )
        record_event(
            self.project_root,
            "capsule-session",
            {
                "event_id": "assistant",
                "type": "assistant_stop",
                "assistant_summary": (
                    "Confirmed: first bad state repeats\n"
                    "Refuted: debug heap is causal\n"
                    "Unknown: exploitability\n"
                    "Next test: toggle only delivery route"
                ),
            },
        )
        capsule = build_capsule(self.project_root, "capsule-session", "test")
        parsed = load_capsule_yaml(dump_capsule_yaml(capsule))
        self.assertEqual(parsed, capsule)
        self.assertEqual(parsed["schema_version"], CAPSULE_SCHEMA_VERSION)
        self.assertEqual(parsed["completion_floor"], "RCE_REQUIRED")
        self.assertEqual(parsed["completion_status"], "RCE_NOT_PROVEN_IN_DERIVED_STATE")
        self.assertIn("first bad state repeats", parsed["confirmed_native_facts"])
        self.assertIn("debug heap is causal", parsed["refuted_hypotheses"])
        self.assertEqual(
            parsed["exact_target"].split(" / ")[0],
            "ExampleProduct native vulnerability discovery prompt",
        )

    def test_rce_proof_requires_an_explicit_positive_rce_statement(self) -> None:
        self.assertTrue(
            text_claims_rce_proof(
                "RCE was proven with reproducible attacker-controlled code execution."
            )
        )
        self.assertTrue(text_claims_rce_proof("공격자 제어 코드 실행을 재현했습니다."))
        self.assertFalse(
            text_claims_rce_proof("RCE proof failed; the crash was confirmed.")
        )
        self.assertFalse(
            text_claims_rce_proof(
                "RCE remains possible; heap corruption was confirmed."
            )
        )

    def test_latest_explicit_status_wins_across_the_trajectory(self) -> None:
        record_event(
            self.project_root,
            "trajectory-session",
            {
                "event_id": "prompt",
                "type": "user_prompt",
                "prompt": "Find an RCE. Hypothesis: importer lifetime crosses cleanup",
            },
        )
        record_event(
            self.project_root,
            "trajectory-session",
            {
                "event_id": "tool",
                "type": "tool_result",
                "tool_family": "ida",
                "tool_name": "mcp__idalib__decompile",
                "request_summary": "consumer at 0x401000",
                "response_summary": "Confirmed: debug heap is causal",
                "response_capture": {"ref": "research/.agent-state/tool.json"},
            },
        )
        record_event(
            self.project_root,
            "trajectory-session",
            {
                "event_id": "assistant-1",
                "type": "assistant_stop",
                "assistant_summary": (
                    "Method: matched route comparison\n"
                    "Relationship: dispatcher creates the object consumed by parser\n"
                    "Runtime state: post-init handoff reaches importer\n"
                    "Primitive: null dereference only"
                ),
            },
        )
        record_event(
            self.project_root,
            "trajectory-session",
            {
                "event_id": "assistant-2",
                "type": "assistant_stop",
                "assistant_summary": (
                    "Refuted: debug heap is causal\n"
                    "Exploitability: no attacker-controlled write\n"
                    "RCE: not proven\n"
                    "Next test: preserve handoff and vary only the input byte"
                ),
            },
        )

        capsule = build_capsule(self.project_root, "trajectory-session", "test")
        self.assertNotIn("debug heap is causal", capsule["confirmed_native_facts"])
        self.assertIn("debug heap is causal", capsule["refuted_hypotheses"])
        self.assertEqual(
            capsule["claim_boundaries"]["primitive"], "null dereference only"
        )
        self.assertEqual(capsule["claim_boundaries"]["rce"], "not proven")
        self.assertEqual(
            capsule["completion_status"], "RCE_NOT_PROVEN_IN_DERIVED_STATE"
        )
        self.assertIn("matched route comparison", capsule["methodology_notes"])
        self.assertIn(
            "dispatcher creates the object", capsule["cross_function_relationships"][0]
        )

    def test_recovery_is_bounded_and_keeps_only_two_recent_tool_pairs(self) -> None:
        record_event(
            self.project_root,
            "bounded-session",
            {
                "event_id": "prompt",
                "type": "user_prompt",
                "prompt": "Find and prove an authorized native RCE",
            },
        )
        for index in range(3):
            record_event(
                self.project_root,
                "bounded-session",
                {
                    "event_id": f"tool-{index}",
                    "type": "tool_result",
                    "tool_family": "ida",
                    "tool_name": f"mcp__idalib__tool_{index}",
                    "request_summary": f"request-{index}-" + "R" * 900,
                    "response_summary": f"response-{index}-" + "S" * 2_000,
                    "request_capture": {
                        "ref": f"research/.agent-state/request-{index}.json"
                    },
                    "response_capture": {
                        "ref": f"research/.agent-state/response-{index}.json"
                    },
                },
            )
        record_event(
            self.project_root,
            "bounded-session",
            {
                "event_id": "assistant",
                "type": "assistant_stop",
                "assistant_summary": (
                    "Confirmed: importer reached\n"
                    "Unknown: file-derived control\n"
                    "Next test: compare the exact control"
                ),
            },
        )

        result = checkpoint_before_compaction(
            self.project_root, "bounded-session", "test"
        )
        self.assertEqual(result["active"], "true")
        recent_path = self.project_root / result["recent_tools"]
        recent_lines = recent_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(recent_lines), 2)
        self.assertNotIn("mcp__idalib__tool_0", recent_path.read_text(encoding="utf-8"))

        context = render_recovery_context(self.project_root, "bounded-session")
        self.assertLessEqual(len(context), MAX_RECOVERY_CONTEXT_CHARS)
        self.assertLessEqual(len(context.encode("utf-8")), MAX_RECOVERY_CONTEXT_BYTES)
        self.assertIn("Completion floor: RCE_REQUIRED", context)
        self.assertIn("mcp__idalib__tool_1", context)
        self.assertIn("mcp__idalib__tool_2", context)
        self.assertNotIn("mcp__idalib__tool_0", context)
        capsule = load_capsule_yaml(
            (self.project_root / result["capsule"]).read_text(encoding="utf-8")
        )
        self.assertTrue(
            all(
                "/.agent-state/" not in pointer
                for pointer in capsule["evidence_pointers"]
            )
        )
        self.assertTrue(capsule["derived_capture_pointers"])

    def test_recovery_reinjects_methodology_notes(self) -> None:
        record_event(
            self.project_root,
            "method-session",
            {
                "event_id": "tool",
                "type": "tool_result",
                "tool_family": "ida",
                "tool_name": "mcp__idalib__decompile",
                "request_summary": "inspect the consumer",
                "response_summary": "Methodology: preserve route and vary one input",
            },
        )

        checkpoint_before_compaction(self.project_root, "method-session", "test")
        context = render_recovery_context(self.project_root, "method-session")

        self.assertIn("methodology: preserve route and vary one input", context)

    def test_deterministic_a_b_c_d_recovery_fidelity_smoke(self) -> None:
        report = run_smoke_evaluation()
        repeated = run_smoke_evaluation()

        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["model_calls"], 0)
        self.assertEqual(report, repeated)
        for arm, expected in EXPECTED_RECALL.items():
            self.assertEqual(set(report["arms"][arm]["recalled"]), expected)
        self.assertEqual(
            report["arms"]["D"]["recall_count"],
            len(MARKERS),
        )
        self.assertGreater(
            report["arms"]["D"]["recall_count"],
            report["arms"]["C"]["recall_count"],
        )
        self.assertLessEqual(
            report["arms"]["D"]["recovery_bytes"], MAX_RECOVERY_CONTEXT_BYTES
        )

    def test_only_contained_canonical_evidence_pointers_are_kept(self) -> None:
        record_event(
            self.project_root,
            "pointer-session",
            {
                "event_id": "tool",
                "type": "tool_result",
                "tool_family": "ida",
                "tool_name": "mcp__idalib__decompile",
                "request_summary": "inspect consumer",
                "response_summary": (
                    "Confirmed: see research/active/example/evidence/native/log.txt\n"
                    "Ignore ../../outside/evidence/stolen.txt and "
                    "research/.agent-state/evidence/derived.txt"
                ),
            },
        )

        capsule = build_capsule(self.project_root, "pointer-session", "test")
        self.assertEqual(
            capsule["evidence_pointers"],
            ["research/active/example/evidence/native/log.txt"],
        )

    def test_guard_continuation_does_not_replace_the_user_objective(self) -> None:
        record_event(
            self.project_root,
            "objective-session",
            {
                "event_id": "prompt-user",
                "type": "user_prompt",
                "prompt_origin": "user",
                "prompt": "Find a reproducible RCE in the selected import route",
            },
        )
        record_event(
            self.project_root,
            "objective-session",
            {
                "event_id": "tool",
                "type": "tool_result",
                "tool_family": "ida",
                "tool_name": "mcp__idalib__decompile",
                "request_summary": "inspect consumer",
                "response_summary": "candidate only",
            },
        )
        record_event(
            self.project_root,
            "objective-session",
            {
                "event_id": "prompt-guard",
                "type": "user_prompt",
                "prompt_origin": "completion_guard",
                "prompt": "Continue because the completion floor was not met",
            },
        )

        capsule = build_capsule(self.project_root, "objective-session", "test")
        self.assertEqual(
            capsule["objective"],
            "Find a reproducible RCE in the selected import route",
        )


class RetrieverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.project_root = Path(self.temporary.name)
        self.findings = (
            self.project_root / "research/active/closed-source-rce/example/findings"
        )
        self.findings.mkdir(parents=True)
        (self.findings / "FIND-0001.md").write_text(
            "# Lifetime UAF\nrepeated native use after free pointer identity evidence/one/log.txt\n",
            encoding="utf-8",
        )
        (self.findings / "FIND-0002.md").write_text(
            "# Integer write\nfile-derived integer controls native write evidence/two/log.txt\n",
            encoding="utf-8",
        )
        template = (
            self.project_root
            / "research/active/closed-source-rce/templates/finding-card.md"
        )
        template.parent.mkdir(parents=True)
        template.write_text(
            "# Template native write use after free\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_only_promoted_finding_paths_are_indexed(self) -> None:
        cards = discover_cards(
            self.project_root, Path("research/active/closed-source-rce")
        )
        self.assertEqual(
            [path.name for path in cards], ["FIND-0001.md", "FIND-0002.md"]
        )
        index = build_index(self.project_root)
        results = bm25_search(index, "use after free lifetime pointer", top=3)
        self.assertEqual(
            results[0]["path"],
            "research/active/closed-source-rce/example/findings/FIND-0001.md",
        )
        self.assertLessEqual(len(results), 3)
        cache = (
            self.project_root
            / "research/.agent-state/closed-source/index/bm25-cache/finding-cards.json"
        )
        json.loads(cache.read_text(encoding="utf-8"))

    def test_top_is_capped(self) -> None:
        with self.assertRaises(ValueError):
            bm25_search({"documents": []}, "query", top=4)
        with self.assertRaises(ValueError):
            bm25_search({"documents": []}, "Q" * 4_001, top=3)


if __name__ == "__main__":
    unittest.main()
