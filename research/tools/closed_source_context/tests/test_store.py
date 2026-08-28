from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from research.tools.closed_source_context import store


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.project_root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_session_id_cannot_escape_project(self) -> None:
        run_dir = store.run_directory(self.project_root, "../../outside/../session")
        self.assertTrue(run_dir.is_relative_to(self.project_root.resolve()))
        self.assertNotIn("..", run_dir.name)

    def test_recognized_secrets_are_not_persisted(self) -> None:
        fake_openai_key = "sk-test-1234567890ABCDEFG"
        fake_bearer = "Bearer fake-token-1234567890"
        fake_aws_key = "AKIAABCDEFGHIJKLMNOP"
        metadata = store.write_capture(
            self.project_root,
            "secret-test",
            "evt-secret",
            "response",
            {
                "output": (
                    f"OPENAI_API_KEY={fake_openai_key} Authorization: {fake_bearer} AWS={fake_aws_key}"
                ),
                "password": "fake-password-value",
            },
        )
        saved = (self.project_root / metadata["ref"]).read_text(encoding="utf-8")
        self.assertNotIn(fake_openai_key, saved)
        self.assertNotIn("fake-token-1234567890", saved)
        self.assertNotIn("fake-password-value", saved)
        self.assertNotIn(fake_aws_key, saved)
        self.assertIn("REDACTED", saved)

    def test_large_capture_records_truncation_and_full_redacted_hash(self) -> None:
        metadata = store.write_capture(
            self.project_root,
            "large-test",
            "evt-large",
            "response",
            "A" * (store.MAX_CAPTURE_BYTES + 1000),
        )
        self.assertTrue(metadata["stored_capture_truncated"])
        saved = json.loads(
            (self.project_root / metadata["ref"]).read_text(encoding="utf-8")
        )
        self.assertTrue(saved["capture_truncated"])
        self.assertEqual(saved["redacted_sha256"], metadata["redacted_sha256"])

    def test_replayed_capture_does_not_overwrite_first_event(self) -> None:
        first = store.write_capture(
            self.project_root,
            "replay-test",
            "evt-replay",
            "response",
            {"output": "first"},
        )
        replay = store.write_capture(
            self.project_root,
            "replay-test",
            "evt-replay",
            "response",
            {"output": "different"},
        )
        saved = json.loads(
            (self.project_root / first["ref"]).read_text(encoding="utf-8")
        )
        self.assertEqual(saved["output"], "first")
        self.assertEqual(first, replay)
        if os.name != "nt":
            mode = stat.S_IMODE((self.project_root / first["ref"]).stat().st_mode)
            self.assertEqual(mode, 0o600)

    def test_concurrent_append_is_atomic_and_idempotent(self) -> None:
        same_event = {"event_id": "evt-same", "type": "test"}
        with ThreadPoolExecutor(max_workers=12) as executor:
            list(
                executor.map(
                    lambda _: store.record_event(
                        self.project_root, "concurrent", same_event
                    ),
                    range(48),
                )
            )
        checkpoint = (
            store.run_directory(self.project_root, "concurrent") / "checkpoint.jsonl"
        )
        lines = checkpoint.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["event_id"], "evt-same")

        unique_events = [
            {"event_id": f"evt-{index}", "type": "test"} for index in range(40)
        ]
        with ThreadPoolExecutor(max_workers=12) as executor:
            list(
                executor.map(
                    lambda event: store.record_event(
                        self.project_root, "concurrent", event
                    ),
                    unique_events,
                )
            )
        parsed = [
            json.loads(line)
            for line in checkpoint.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(len(parsed), 41)
        self.assertEqual(len({event["event_id"] for event in parsed}), 41)


if __name__ == "__main__":
    unittest.main()
