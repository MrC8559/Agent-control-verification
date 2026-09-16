from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from agent_control_verification.codex_evidence_guard import collect_codex_probe_strict
from agent_control_verification.codex_integration import (
    CODEX_TARGET_VERSION,
    prepare_codex_probe,
    run_codex_hook,
)
from agent_control_verification.evidence import validate_evidence_bundle
from agent_control_verification.model import Verdict


T0 = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 9, 16, 12, 1, tzinfo=timezone.utc)
PATCH = "*** Begin Patch\n*** Update File: acv-marker.txt\n@@\n-BASELINE\n+CHANGED\n*** End Patch"


def payload(workspace: Path, event_name: str, tool_use_id: str) -> dict:
    value = {
        "session_id": "session-1",
        "turn_id": "turn-1",
        "agent_id": None,
        "agent_type": None,
        "transcript_path": None,
        "cwd": str(workspace),
        "hook_event_name": event_name,
        "model": "test-model",
        "permission_mode": "default",
        "tool_name": "apply_patch",
        "tool_input": {"command": PATCH},
        "tool_use_id": tool_use_id,
    }
    if event_name == "PostToolUse":
        value["tool_response"] = {"ok": True}
    return value


class CodexEvidenceGuardTests(unittest.TestCase):
    def _record(self, log: Path, value: dict, mode: str, when: datetime) -> None:
        run_codex_hook(
            json.dumps(value),
            mode=mode,
            log_path=log,
            recorded_at=when,
        )

    def test_deny_cannot_pass_when_unpaired_post_tool_use_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "probe"
            paths = prepare_codex_probe(workspace, pre_mode="deny", python_executable="python")
            self._record(
                paths.log_file,
                payload(workspace, "PreToolUse", "call-1"),
                "deny",
                T0,
            )
            self._record(
                paths.log_file,
                payload(workspace, "PostToolUse", "unexpected-call"),
                "observe",
                T1,
            )

            collection = collect_codex_probe_strict(
                workspace,
                codex_version=CODEX_TARGET_VERSION,
            )

            self.assertEqual(collection.result.verdict, Verdict.FAIL)
            self.assertIn("unpaired PostToolUse", collection.result.reason)
            self.assertIsNotNone(collection.bundle)
            validate_evidence_bundle(collection.bundle)
            self.assertTrue(
                any(
                    ref.startswith("codex-post-unpaired:")
                    for ref in collection.bundle["evidence"]["audit_refs"]
                )
            )

    def test_allow_cannot_pass_when_an_extra_unpaired_post_tool_use_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "probe"
            paths = prepare_codex_probe(workspace, pre_mode="allow", python_executable="python")
            self._record(
                paths.log_file,
                payload(workspace, "PreToolUse", "call-1"),
                "allow",
                T0,
            )
            paths.marker_file.write_text("CHANGED\n", encoding="utf-8")
            self._record(
                paths.log_file,
                payload(workspace, "PostToolUse", "call-1"),
                "observe",
                T1,
            )
            self._record(
                paths.log_file,
                payload(workspace, "PostToolUse", "unexpected-call"),
                "observe",
                T1,
            )

            collection = collect_codex_probe_strict(
                workspace,
                codex_version=CODEX_TARGET_VERSION,
            )

            self.assertEqual(collection.result.verdict, Verdict.INCONCLUSIVE)
            self.assertIn("unexpected_post_tool_use_record", collection.bundle["evidence"]["missing"])
            validate_evidence_bundle(collection.bundle)


if __name__ == "__main__":
    unittest.main()
