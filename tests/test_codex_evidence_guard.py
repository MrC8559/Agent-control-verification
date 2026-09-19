from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from agent_control_verification.codex_evidence import collect_codex_probe
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

    def test_incompatible_or_unordered_records_are_inconclusive(self):
        cases = (
            "reported_false_pass", "session", "turn", "agent", "tool",
            "missing_session", "missing_turn", "missing_post_time", "missing_pre_time",
            "invalid_time", "naive_time", "backwards_time", "backwards_log",
            "future_pre", "future_post", "unpaired_backwards", "unpaired_invalid_time",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                workspace = Path(tmp) / "probe"
                paths = prepare_codex_probe(workspace, pre_mode="allow")
                self._record(paths.log_file, payload(workspace, "PreToolUse", "call-1"), "allow", T0)
                self._record(paths.log_file, payload(workspace, "PostToolUse", "call-1"), "observe", T1)
                records = [json.loads(line) for line in paths.log_file.read_text().splitlines()]
                pre, post = records
                if case in {"session", "turn", "agent"}:
                    post[f"{case}_ref"] = "sha256:" + "a" * 64
                elif case == "tool":
                    post["tool_name"] = "other-tool"
                elif case in {"missing_session", "missing_turn"}:
                    field = case.removeprefix("missing_") + "_ref"
                    pre.pop(field)
                    post.pop(field)
                elif case == "missing_post_time":
                    post.pop("recorded_at")
                elif case == "missing_pre_time":
                    pre.pop("recorded_at")
                elif case in {"invalid_time", "unpaired_invalid_time"}:
                    post["recorded_at"] = "invalid"
                elif case == "naive_time":
                    post["recorded_at"] = "2026-09-16T12:01:00"
                elif case in {"backwards_time", "unpaired_backwards", "reported_false_pass"}:
                    pre["recorded_at"], post["recorded_at"] = post["recorded_at"], pre["recorded_at"]
                elif case == "backwards_log":
                    records.reverse()
                elif case == "future_pre":
                    pre["recorded_at"] = "2999-01-01T00:00:00Z"
                elif case == "future_post":
                    post["recorded_at"] = "2999-01-01T00:00:00Z"
                if case.startswith("unpaired_"):
                    post["tool_use_ref"] = "sha256:" + "b" * 64
                if case == "reported_false_pass":
                    post["session_ref"] = "sha256:" + "a" * 64
                    post["turn_ref"] = "sha256:" + "b" * 64
                    records.reverse()
                paths.log_file.write_text("\n".join(json.dumps(record) for record in records), encoding="utf-8")
                paths.marker_file.write_bytes(b"CHANGED\n")
                for collector in (collect_codex_probe, collect_codex_probe_strict):
                    with self.subTest(collector=collector.__name__):
                        collection = collector(workspace, codex_version=CODEX_TARGET_VERSION)
                        self.assertEqual(collection.result.verdict, Verdict.INCONCLUSIVE)
                        self.assertEqual(collection.bundle["evidence"]["timeline"], [])
                        self.assertIn("ordered_timeline", collection.bundle["evidence"]["missing"])
                        validate_evidence_bundle(collection.bundle)

    def test_equal_timestamps_preserve_observed_append_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "probe"
            paths = prepare_codex_probe(workspace, pre_mode="allow")
            self._record(paths.log_file, payload(workspace, "PreToolUse", "call-1"), "allow", T0)
            self._record(paths.log_file, payload(workspace, "PostToolUse", "call-1"), "observe", T0)
            paths.marker_file.write_bytes(b"CHANGED\n")
            collection = collect_codex_probe_strict(workspace, codex_version=CODEX_TARGET_VERSION)
            self.assertEqual(collection.result.verdict, Verdict.PASS)
            self.assertEqual(
                [event["kind"] for event in collection.bundle["evidence"]["timeline"]],
                ["decision", "invocation", "effect"],
            )

    def test_deny_and_failure_do_not_claim_order_from_incompatible_records(self):
        for mode in ("deny", "malformed", "exit-error"):
            for case in ("other_session", "missing_pre_time", "backwards_log"):
                with self.subTest(mode=mode, case=case), tempfile.TemporaryDirectory() as tmp:
                    workspace = Path(tmp) / "probe"
                    paths = prepare_codex_probe(workspace, pre_mode=mode)
                    self._record(paths.log_file, payload(workspace, "PreToolUse", "call-1"), mode, T0)
                    if case != "missing_pre_time":
                        self._record(paths.log_file, payload(workspace, "PostToolUse", "call-1"), "observe", T1)
                    records = [json.loads(line) for line in paths.log_file.read_text().splitlines()]
                    if case == "other_session":
                        records[1]["session_ref"] = "sha256:" + "a" * 64
                    elif case == "missing_pre_time":
                        records[0].pop("recorded_at")
                    else:
                        records.reverse()
                    paths.log_file.write_text("\n".join(json.dumps(record) for record in records), encoding="utf-8")
                    collection = collect_codex_probe_strict(workspace, codex_version=CODEX_TARGET_VERSION)
                    self.assertEqual(collection.result.verdict, Verdict.INCONCLUSIVE)
                    self.assertEqual(collection.bundle["evidence"]["timeline"], [])
                    self.assertIn("ordered_timeline", collection.bundle["evidence"]["missing"])
                    validate_evidence_bundle(collection.bundle)

    def test_correlated_input_mutation_still_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "probe"
            paths = prepare_codex_probe(workspace, pre_mode="allow")
            self._record(paths.log_file, payload(workspace, "PreToolUse", "call-1"), "allow", T0)
            post = payload(workspace, "PostToolUse", "call-1")
            post["tool_input"] = {"command": "different action"}
            self._record(paths.log_file, post, "observe", T1)
            paths.marker_file.write_bytes(b"CHANGED\n")
            collection = collect_codex_probe_strict(workspace, codex_version=CODEX_TARGET_VERSION)
            self.assertEqual(collection.result.verdict, Verdict.FAIL)
            self.assertIn("fingerprint", collection.result.reason)

    def test_unpaired_invocation_does_not_invent_a_bound_timeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "probe"
            paths = prepare_codex_probe(workspace, pre_mode="allow")
            self._record(paths.log_file, payload(workspace, "PreToolUse", "call-1"), "allow", T0)
            self._record(paths.log_file, payload(workspace, "PostToolUse", "call-1"), "observe", T1)
            self._record(paths.log_file, payload(workspace, "PostToolUse", "call-2"), "observe", T1)
            paths.marker_file.write_bytes(b"CHANGED\n")
            collection = collect_codex_probe_strict(workspace, codex_version=CODEX_TARGET_VERSION)
            self.assertEqual(collection.result.verdict, Verdict.INCONCLUSIVE)
            self.assertEqual(
                [event["kind"] for event in collection.bundle["evidence"]["timeline"]],
                [],
            )
            self.assertIn("unexpected_post_tool_use_record", collection.bundle["evidence"]["missing"])
            validate_evidence_bundle(collection.bundle)

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

            self.assertEqual(collection.result.verdict, Verdict.INCONCLUSIVE)
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
            paths.marker_file.write_bytes(b"CHANGED\n")
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

    def test_strict_bundle_preserves_redacted_host_and_runtime_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "probe"
            paths = prepare_codex_probe(workspace, pre_mode="deny", python_executable="python")
            self._record(
                paths.log_file,
                payload(workspace, "PreToolUse", "call-1"),
                "deny",
                T0,
            )

            collection = collect_codex_probe_strict(
                workspace,
                codex_version=CODEX_TARGET_VERSION,
            )

            self.assertEqual(collection.result.verdict, Verdict.PASS)
            self.assertIsNotNone(collection.bundle)
            validate_evidence_bundle(collection.bundle)

            model_components = [
                component
                for component in collection.bundle["components"]
                if component["role"] == "model"
            ]
            self.assertEqual(len(model_components), 1)
            self.assertEqual(model_components[0]["name"], "test-model")

            audit_refs = collection.bundle["evidence"]["audit_refs"]
            self.assertTrue(any(ref.startswith("codex-session:sha256:") for ref in audit_refs))
            self.assertTrue(any(ref.startswith("codex-turn:sha256:") for ref in audit_refs))

            environment = collection.bundle["environment"]
            self.assertTrue(environment["python_implementation"])
            self.assertTrue(environment["python_version"])
            self.assertEqual(environment["codex_permission_mode"], "default")
            self.assertEqual(
                environment["hook_config_sha256_collected"],
                hashlib.sha256(paths.hooks_file.read_bytes()).hexdigest(),
            )
            self.assertEqual(len(environment["hook_adapter_sha256_collected"]), 64)
            self.assertEqual(len(environment["hook_entrypoint_sha256_collected"]), 64)

    def test_hook_config_modified_after_prepare_prevents_control_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "probe"
            paths = prepare_codex_probe(workspace, pre_mode="allow", python_executable="python")
            self._record(
                paths.log_file,
                payload(workspace, "PreToolUse", "call-1"),
                "allow",
                T0,
            )
            paths.marker_file.write_bytes(b"CHANGED\n")
            self._record(
                paths.log_file,
                payload(workspace, "PostToolUse", "call-1"),
                "observe",
                T1,
            )

            # Same logical hook configuration, re-serialized differently, simulating
            # a hook file that was swapped or edited after codex-prepare ran and
            # before/while Codex used it.
            config = json.loads(paths.hooks_file.read_text(encoding="utf-8"))
            paths.hooks_file.write_text(json.dumps(config, indent=4) + "\n", encoding="utf-8")

            collection = collect_codex_probe_strict(
                workspace,
                codex_version=CODEX_TARGET_VERSION,
            )

            self.assertEqual(collection.result.verdict, Verdict.INCONCLUSIVE)
            self.assertIn("hook configuration digest", collection.result.reason)
            self.assertIn("consistent_hook_configuration", collection.bundle["evidence"]["missing"])
            environment = collection.bundle["environment"]
            self.assertIn("hook_config_sha256_prepared", environment)
            self.assertIn("hook_config_sha256_collected", environment)
            self.assertNotEqual(
                environment["hook_config_sha256_prepared"],
                environment["hook_config_sha256_collected"],
            )
            validate_evidence_bundle(collection.bundle)

    def test_matching_hook_config_digest_records_both_values_without_forcing_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "probe"
            paths = prepare_codex_probe(workspace, pre_mode="deny", python_executable="python")
            self._record(
                paths.log_file,
                payload(workspace, "PreToolUse", "call-1"),
                "deny",
                T0,
            )

            collection = collect_codex_probe_strict(
                workspace,
                codex_version=CODEX_TARGET_VERSION,
            )

            self.assertEqual(collection.result.verdict, Verdict.PASS)
            environment = collection.bundle["environment"]
            self.assertEqual(
                environment["hook_config_sha256_prepared"],
                environment["hook_config_sha256_collected"],
            )

    def test_missing_collected_hook_config_digest_is_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "probe"
            paths = prepare_codex_probe(workspace, pre_mode="deny", python_executable="python")
            self._record(
                paths.log_file,
                payload(workspace, "PreToolUse", "call-1"),
                "deny",
                T0,
            )
            paths.hooks_file.unlink()

            collection = collect_codex_probe_strict(
                workspace,
                codex_version=CODEX_TARGET_VERSION,
            )

            self.assertEqual(collection.result.verdict, Verdict.INCONCLUSIVE)
            self.assertIn(
                "hook_config_sha256_collected",
                collection.bundle["evidence"]["missing"],
            )
            self.assertNotIn(
                "hook_config_sha256_collected",
                collection.bundle["environment"],
            )
            validate_evidence_bundle(collection.bundle)


if __name__ == "__main__":
    unittest.main()
