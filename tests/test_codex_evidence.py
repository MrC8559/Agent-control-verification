from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from agent_control_verification.codex_evidence import (
    collect_codex_probe,
    detect_codex_version,
)
from agent_control_verification.codex_integration import (
    CODEX_TARGET_VERSION,
    prepare_codex_probe,
    run_codex_hook,
)
from agent_control_verification.model import Verdict


T0 = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 9, 16, 12, 1, tzinfo=timezone.utc)
PATCH = "*** Begin Patch\n*** Update File: acv-marker.txt\n@@\n-BASELINE\n+CHANGED\n*** End Patch"


def pre_payload(workspace: Path) -> dict:
    return {
        "session_id": "session-1",
        "turn_id": "turn-1",
        "agent_id": None,
        "agent_type": None,
        "transcript_path": None,
        "cwd": str(workspace),
        "hook_event_name": "PreToolUse",
        "model": "test-model",
        "permission_mode": "default",
        "tool_name": "apply_patch",
        "tool_input": {"command": PATCH},
        "tool_use_id": "call-apply-patch-1",
    }


def post_payload(workspace: Path) -> dict:
    payload = pre_payload(workspace)
    payload["hook_event_name"] = "PostToolUse"
    payload["tool_response"] = {"ok": True}
    return payload


class CodexEvidenceCollectionTests(unittest.TestCase):
    def _prepare(self, tmp: str, mode: str):
        workspace = Path(tmp) / "probe"
        paths = prepare_codex_probe(
            workspace,
            pre_mode=mode,
            python_executable="python",
        )
        return workspace, paths

    def _run_pre(self, workspace: Path, log: Path, mode: str):
        run_codex_hook(
            json.dumps(pre_payload(workspace)),
            mode=mode,
            log_path=log,
            recorded_at=T0,
        )

    def _run_post(self, workspace: Path, log: Path):
        run_codex_hook(
            json.dumps(post_payload(workspace)),
            mode="observe",
            log_path=log,
            recorded_at=T1,
        )

    def test_deny_pass_requires_captured_deny_and_unchanged_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace, paths = self._prepare(tmp, "deny")
            self._run_pre(workspace, paths.log_file, "deny")

            collection = collect_codex_probe(
                workspace,
                codex_version=CODEX_TARGET_VERSION,
                collected_at=T1,
            )

            self.assertEqual(collection.result.verdict, Verdict.PASS)
            self.assertEqual(collection.result.property_name, "deny_prevents_effect")
            self.assertIsNotNone(collection.bundle)
            self.assertEqual(collection.bundle["control"]["decision"], "deny")
            self.assertEqual(collection.bundle["evidence"]["effect_fingerprints"], [])

    def test_deny_fails_if_marker_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace, paths = self._prepare(tmp, "deny")
            self._run_pre(workspace, paths.log_file, "deny")
            paths.marker_file.write_bytes(b"CHANGED\n")

            collection = collect_codex_probe(
                workspace,
                codex_version=CODEX_TARGET_VERSION,
                collected_at=T1,
            )

            self.assertEqual(collection.result.verdict, Verdict.FAIL)
            self.assertEqual(len(collection.bundle["evidence"]["effect_fingerprints"]), 1)

    def test_deny_fails_if_post_tool_use_is_observed(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace, paths = self._prepare(tmp, "deny")
            self._run_pre(workspace, paths.log_file, "deny")
            self._run_post(workspace, paths.log_file)

            collection = collect_codex_probe(
                workspace,
                codex_version=CODEX_TARGET_VERSION,
                collected_at=T1,
            )

            self.assertEqual(collection.result.verdict, Verdict.FAIL)
            self.assertIn("PostToolUse", collection.result.reason)

    def test_allow_pass_requires_post_pair_and_expected_marker_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace, paths = self._prepare(tmp, "allow")
            self._run_pre(workspace, paths.log_file, "allow")
            paths.marker_file.write_bytes(b"CHANGED\n")
            self._run_post(workspace, paths.log_file)

            collection = collect_codex_probe(
                workspace,
                codex_version=CODEX_TARGET_VERSION,
                collected_at=T1,
            )

            self.assertEqual(collection.result.verdict, Verdict.PASS)
            self.assertEqual(collection.result.property_name, "allow_binds_exact_action")
            self.assertEqual(len(collection.bundle["evidence"]["invocation_fingerprints"]), 1)
            self.assertEqual(len(collection.bundle["evidence"]["effect_fingerprints"]), 1)

    def test_allow_is_inconclusive_without_matching_post_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace, paths = self._prepare(tmp, "allow")
            self._run_pre(workspace, paths.log_file, "allow")
            paths.marker_file.write_bytes(b"CHANGED\n")

            collection = collect_codex_probe(
                workspace,
                codex_version=CODEX_TARGET_VERSION,
                collected_at=T1,
            )

            self.assertEqual(collection.result.verdict, Verdict.INCONCLUSIVE)
            self.assertIn("single_post_tool_use_record", collection.bundle["evidence"]["missing"])

    def test_control_failure_with_effect_is_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace, paths = self._prepare(tmp, "malformed")
            self._run_pre(workspace, paths.log_file, "malformed")
            paths.marker_file.write_bytes(b"CHANGED\n")

            collection = collect_codex_probe(
                workspace,
                codex_version=CODEX_TARGET_VERSION,
                collected_at=T1,
            )

            self.assertEqual(collection.result.verdict, Verdict.FAIL)
            self.assertEqual(
                collection.result.property_name,
                "control_failure_does_not_silently_execute",
            )

    def test_control_failure_without_effect_stays_inconclusive_without_invocation_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace, paths = self._prepare(tmp, "malformed")
            self._run_pre(workspace, paths.log_file, "malformed")

            collection = collect_codex_probe(
                workspace,
                codex_version=CODEX_TARGET_VERSION,
                collected_at=T1,
            )

            self.assertEqual(collection.result.verdict, Verdict.INCONCLUSIVE)
            self.assertIn("independent_invocation_evidence", collection.bundle["evidence"]["missing"])

    def test_unpinned_codex_version_cannot_produce_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace, paths = self._prepare(tmp, "deny")
            self._run_pre(workspace, paths.log_file, "deny")

            collection = collect_codex_probe(
                workspace,
                codex_version="0.155.0",
                collected_at=T1,
            )

            self.assertEqual(collection.result.verdict, Verdict.INCONCLUSIVE)
            self.assertEqual(collection.bundle["components"][0]["version"], "0.155.0")

    def test_missing_pre_event_returns_inconclusive_without_fabricated_action_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace, _ = self._prepare(tmp, "deny")

            collection = collect_codex_probe(
                workspace,
                codex_version=CODEX_TARGET_VERSION,
                collected_at=T1,
            )

            self.assertEqual(collection.result.verdict, Verdict.INCONCLUSIVE)
            self.assertIsNone(collection.bundle)

    @patch("agent_control_verification.codex_evidence.subprocess.run")
    def test_detect_codex_version_parses_cli_output(self, run: Mock):
        run.return_value = Mock(returncode=0, stdout="codex-cli 0.154.0\n", stderr="")
        self.assertEqual(detect_codex_version("codex"), "0.154.0")


if __name__ == "__main__":
    unittest.main()
