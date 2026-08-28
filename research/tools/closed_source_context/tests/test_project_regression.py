from __future__ import annotations

import json
import unittest
from pathlib import Path

from research.tools.closed_source_context.compactor import load_capsule_yaml

PROJECT_ROOT = Path(__file__).resolve().parents[4]


class ProjectRegressionTests(unittest.TestCase):
    def test_root_scope_is_target_independent_and_template_is_generic(
        self,
    ) -> None:
        agents = (PROJECT_ROOT / "AGENTS.md").read_text(encoding="utf-8")
        prompt = (
            PROJECT_ROOT / "research/templates/closed-source-rce/DISCOVERY-PROMPT.md"
        ).read_text(encoding="utf-8")
        self.assertIn("[PRODUCT_OR_COMPONENT]", prompt)
        self.assertIn("[AUTHORIZED_INPUT_FORMATS_AND_OWNED_CONSUMERS]", prompt)
        self.assertIn("[EXCLUDED_FORMATS_PRODUCTS_COMPONENTS_AND_OTHER_OWNERS]", prompt)
        self.assertIn("A bounded failed row is not lane closure", prompt)
        self.assertIn("no concrete development hypothesis remains", prompt)
        self.assertIn("Expanding that boundary", agents)
        self.assertIn("RCE is the minimum success condition", prompt)
        self.assertEqual(prompt.count("RCE is the minimum success condition"), 1)
        self.assertIn("A crash, denial of service", prompt)
        self.assertNotIn("Complete only with either", prompt)
        self.assertIn("Keep the repository-root `AGENTS.md` target-independent", agents)
        self.assertIn("A target instance is the corresponding directory", agents)
        self.assertIn("Debugger configuration and observation mode", agents)
        self.assertNotIn("Do not assume CDB always changes", agents)
        self.assertNotIn("`-hd`", agents)
        self.assertNotIn("# Reusable synthesis", agents)
        self.assertIn("out of the shared Git history", agents)
        self.assertNotIn("Do not rebuild a pipeline", prompt)
        self.assertNotIn("$cdb-native-validation", prompt)
        self.assertNotIn("same-day `llm-log.md`", prompt)

        skill = (
            PROJECT_ROOT / ".agents/skills/cdb-native-validation/SKILL.md"
        ).read_text(encoding="utf-8")
        self.assertLessEqual(len(agents.split()), 500)
        self.assertLessEqual(len(prompt.split()), 320)
        self.assertLessEqual(len(skill.split()), 600)

    def test_machine_facing_files_are_english_only_and_have_no_todos(self) -> None:
        paths = [
            PROJECT_ROOT / "AGENTS.md",
            PROJECT_ROOT / "research/templates/closed-source-rce/DISCOVERY-PROMPT.md",
            PROJECT_ROOT / ".agents/skills/cdb-native-validation/SKILL.md",
            PROJECT_ROOT
            / ".agents/skills/cdb-native-validation/references/cdb-commands.md",
            PROJECT_ROOT / "research/tools/closed_source_context/CONTRACT.md",
            PROJECT_ROOT
            / "research/templates/closed-source-rce/target-instance/findings/FIND-0000.template.md",
            PROJECT_ROOT / ".codex/hooks.json",
        ]
        for path in paths:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("TODO", text)
            self.assertNotIn("Korean footnotes", text)
            self.assertFalse(
                any("\uac00" <= character <= "\ud7a3" for character in text), path
            )
        skill = paths[2].read_text(encoding="utf-8")
        frontmatter = skill.split("---", 2)[1]
        keys = [
            line.split(":", 1)[0] for line in frontmatter.splitlines() if ":" in line
        ]
        self.assertEqual(keys, ["name", "description"])
        hooks = json.loads(paths[-1].read_text(encoding="utf-8"))
        session_start_handler = hooks["hooks"]["SessionStart"][0]["hooks"][0]
        self.assertEqual(session_start_handler["additionalContextLimit"], 6000)

        contract = paths[4].read_text(encoding="utf-8")
        self.assertIn("IMPLEMENTED PAPER-ADAPTED V2", contract)
        self.assertIn("at most two recent tool pairs", contract)
        self.assertIn("4,800 characters and 6,000 UTF-8 bytes", contract)
        self.assertIn("cannot replace the latest real user objective", contract)
        self.assertIn("does not reproduce Slyp's agent scaffold", contract)
        self.assertIn(
            "automated tests and live manual and forced automatic compaction acceptance passed",
            contract,
        )
        self.assertIn("morphologically negated output", contract)
        self.assertIn("methodology reinjection", contract)
        self.assertIn("A and B retain 0/15 dynamic markers", contract)
        self.assertIn("D retains 15/15 in 1,996 UTF-8 bytes", contract)

    def test_capsule_template_has_required_fields(self) -> None:
        template = (
            PROJECT_ROOT
            / "research/tools/closed_source_context/schemas/capsule.template.yaml"
        ).read_text(encoding="utf-8")
        capsule = load_capsule_yaml(template)
        schema = json.loads(
            (
                PROJECT_ROOT
                / "research/tools/closed_source_context/schemas/capsule.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(set(schema["required"]), set(capsule))
        self.assertEqual(capsule["schema_version"], 2)
        self.assertEqual(capsule["completion_floor"], "RCE_REQUIRED")
        self.assertIn("analysis_active", capsule)
        self.assertIn("checkpoint_ref", capsule)
        self.assertIn("claim_boundaries", capsule)
        self.assertIn("derived_capture_pointers", capsule)


if __name__ == "__main__":
    unittest.main()
