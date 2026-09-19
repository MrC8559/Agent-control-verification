from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from agent_control_verification.codex_integration import (
    CODEX_TARGET_VERSION,
    CodexIntegrationError,
    build_codex_hooks_config,
    pair_pre_post_records,
    parse_codex_hook_payload,
    prepare_codex_probe,
    read_hook_records,
    run_codex_hook,
)


T0 = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
PATCH = "*** Begin Patch\n*** Update File: acv-marker.txt\n@@\n-BASELINE\n+CHANGED\n*** End Patch"


def pre_payload() -> dict:
    return {
        "session_id": "session-secretish-1",
        "turn_id": "turn-1",
        "agent_id": None,
        "agent_type": None,
        "transcript_path": None,
        "cwd": "/tmp/acv-probe",
        "hook_event_name": "PreToolUse",
        "model": "test-model",
        "permission_mode": "default",
        "tool_name": "apply_patch",
        "tool_input": {"command": PATCH},
        "tool_use_id": "call-apply-patch-1",
    }


def post_payload() -> dict:
    payload = pre_payload()
    payload["hook_event_name"] = "PostToolUse"
    payload["tool_response"] = "Success. Updated files."
    return payload


class CodexHookContractTests(unittest.TestCase):
    def test_parse_accepts_version_pinned_apply_patch_pre_event(self):
        event = parse_codex_hook_payload(pre_payload())
        self.assertEqual(event.event_name, "PreToolUse")
        self.assertEqual(event.tool_name, "apply_patch")
        self.assertEqual(event.tool_use_id, "call-apply-patch-1")

    def test_adapter_rejects_other_tool_paths(self):
        payload = pre_payload()
        payload["tool_name"] = "Bash"
        with self.assertRaises(CodexIntegrationError):
            parse_codex_hook_payload(payload)

    def test_deny_output_matches_codex_pretool_shape_and_log_is_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "events.jsonl"
            stdout, exit_code = run_codex_hook(
                json.dumps(pre_payload()),
                mode="deny",
                log_path=log,
                recorded_at=T0,
            )
            output = json.loads(stdout)
            specific = output["hookSpecificOutput"]
            self.assertEqual(exit_code, 0)
            self.assertEqual(specific["hookEventName"], "PreToolUse")
            self.assertEqual(specific["permissionDecision"], "deny")

            log_text = log.read_text(encoding="utf-8")
            self.assertNotIn(PATCH, log_text)
            self.assertNotIn("session-secretish-1", log_text)
            records = read_hook_records(log)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["mode"], "deny")
            self.assertEqual(records[0]["tool_name"], "apply_patch")
            self.assertTrue(records[0]["tool_input_fingerprint"])

    def test_allow_echoes_exact_input_as_updated_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            stdout, exit_code = run_codex_hook(
                json.dumps(pre_payload()),
                mode="allow",
                log_path=Path(tmp) / "events.jsonl",
                recorded_at=T0,
            )
            output = json.loads(stdout)
            specific = output["hookSpecificOutput"]
            self.assertEqual(exit_code, 0)
            self.assertEqual(specific["permissionDecision"], "allow")
            self.assertEqual(specific["updatedInput"], pre_payload()["tool_input"])

    def test_malformed_mode_records_event_before_emitting_invalid_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "events.jsonl"
            stdout, exit_code = run_codex_hook(
                json.dumps(pre_payload()),
                mode="malformed",
                log_path=log,
                recorded_at=T0,
            )
            self.assertEqual(exit_code, 0)
            with self.assertRaises(json.JSONDecodeError):
                json.loads(stdout)
            self.assertEqual(read_hook_records(log)[0]["mode"], "malformed")

    def test_exit_error_mode_records_event_and_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "events.jsonl"
            stdout, exit_code = run_codex_hook(
                json.dumps(pre_payload()),
                mode="exit-error",
                log_path=log,
                recorded_at=T0,
            )
            self.assertEqual(stdout, "")
            self.assertEqual(exit_code, 1)
            self.assertEqual(read_hook_records(log)[0]["mode"], "exit-error")

    def test_post_tool_event_is_observational_and_pairs_with_pre(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "events.jsonl"
            run_codex_hook(
                json.dumps(pre_payload()),
                mode="allow",
                log_path=log,
                recorded_at=T0,
            )
            stdout, exit_code = run_codex_hook(
                json.dumps(post_payload()),
                mode="observe",
                log_path=log,
                recorded_at=T0,
            )
            self.assertEqual((stdout, exit_code), ("{}", 0))
            records = read_hook_records(log)
            pairs = pair_pre_post_records(records)
            self.assertEqual(len(pairs), 1)
            pair = next(iter(pairs.values()))
            self.assertIn("PreToolUse", pair)
            self.assertIn("PostToolUse", pair)
            self.assertEqual(pair["PostToolUse"]["mode"], "observe")
            self.assertTrue(pair["PostToolUse"]["tool_response_fingerprint"])


class CodexProbePreparationTests(unittest.TestCase):
    def test_marker_baseline_digest_matches_exact_lf_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = prepare_codex_probe(Path(tmp) / "probe", pre_mode="deny")
            marker_bytes = paths.marker_file.read_bytes()
            manifest = json.loads(paths.manifest_file.read_text(encoding="utf-8"))
            self.assertEqual(marker_bytes, b"BASELINE\n")
            self.assertEqual(manifest["marker_before_sha256"], hashlib.sha256(marker_bytes).hexdigest())

    def test_config_targets_apply_patch_only(self):
        config = build_codex_hooks_config(
            python_executable="python",
            log_path=Path("/tmp/acv-events.jsonl"),
            pre_mode="deny",
        )
        pre = config["hooks"]["PreToolUse"][0]
        post = config["hooks"]["PostToolUse"][0]
        self.assertEqual(pre["matcher"], "^apply_patch$")
        self.assertEqual(post["matcher"], "^apply_patch$")
        self.assertIn("codex-hook", pre["hooks"][0]["command"])
        self.assertIn("--mode deny", pre["hooks"][0]["command"])
        self.assertIn("--mode observe", post["hooks"][0]["command"])

    def test_prepare_creates_disposable_workspace_without_touching_user_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "probe"
            paths = prepare_codex_probe(
                workspace,
                pre_mode="deny",
                python_executable="python",
            )
            self.assertEqual(paths.marker_file.read_text(encoding="utf-8"), "BASELINE\n")
            hooks = json.loads(paths.hooks_file.read_text(encoding="utf-8"))
            manifest = json.loads(paths.manifest_file.read_text(encoding="utf-8"))
            self.assertEqual(manifest["codex_expected_version"], CODEX_TARGET_VERSION)
            self.assertEqual(manifest["pre_mode"], "deny")
            self.assertEqual(
                manifest["hooks_sha256"],
                hashlib.sha256(paths.hooks_file.read_bytes()).hexdigest(),
            )
            self.assertEqual(hooks["hooks"]["PreToolUse"][0]["matcher"], "^apply_patch$")
            self.assertTrue(str(paths.hooks_file).startswith(str(workspace.resolve())))
            self.assertFalse(paths.log_file.exists())

    def test_prepare_refuses_nonempty_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "existing"
            workspace.mkdir()
            (workspace / "do-not-overwrite.txt").write_text("keep", encoding="utf-8")
            with self.assertRaises(CodexIntegrationError):
                prepare_codex_probe(workspace, pre_mode="deny", python_executable="python")


if __name__ == "__main__":
    unittest.main()
