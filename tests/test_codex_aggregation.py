from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from agent_control_verification.codex_evidence import collect_codex_probe, write_codex_probe_bundle
from agent_control_verification.codex_evidence_guard import collect_codex_probe_strict
from agent_control_verification.codex_integration import (
    CODEX_TARGET_VERSION, CodexIntegrationError, prepare_codex_probe,
    parse_codex_hook_payload, redacted_hook_record,
)
from agent_control_verification.evidence import load_evidence_bundle, render_evidence_bundle
from agent_control_verification.model import Verdict
from test_codex_evidence_guard import payload, T0, T1


class CodexAggregationTests(unittest.TestCase):
    def _prepare(self, mode="deny"):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        paths = prepare_codex_probe(Path(temporary.name) / "probe", pre_mode=mode)
        records = [
            redacted_hook_record(
                parse_codex_hook_payload(payload(paths.workspace, event, "call-1")),
                mode=fixture, recorded_at=timestamp,
            )
            for event, fixture, timestamp in (
                ("PreToolUse", mode, T0), ("PostToolUse", "observe", T1),
            )
        ]
        if mode == "allow":
            paths.marker_file.write_bytes(b"CHANGED\n")
        return paths, records

    def _write(self, paths, records):
        paths.log_file.write_text(
            "\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8",
        )

    def _collect_both(self, paths, records, verdict):
        self._write(paths, records)
        collections = []
        for collector in (collect_codex_probe, collect_codex_probe_strict):
            with self.subTest(collector=collector.__name__):
                collection = collector(paths.workspace, codex_version=CODEX_TARGET_VERSION)
                self.assertEqual(collection.result.verdict, verdict)
                if collection.bundle is not None:
                    self.assertEqual(load_evidence_bundle(json.dumps(collection.bundle)), collection.bundle)
                collections.append(collection)
        return collections

    def test_correlated_failure_survives_unrelated_pre_or_post(self):
        for mode in ("deny", "malformed", "exit-error", "allow"):
            for event in ("PreToolUse", "PostToolUse"):
                with self.subTest(mode=mode, event=event):
                    paths, records = self._prepare(mode)
                    if mode == "allow":
                        records[1]["tool_input_fingerprint"] = "a" * 64
                    expected_action = records[0]["tool_input_fingerprint"]
                    extra = deepcopy(records[0 if event == "PreToolUse" else 1])
                    extra["session_ref"] = "sha256:" + "b" * 64
                    extra["tool_use_ref"] = "sha256:" + "c" * 64
                    if event == "PreToolUse":
                        extra["tool_input_fingerprint"] = "e" * 64
                        extra["model"] = "unrelated-model"
                        records.insert(0, extra)
                    else:
                        records.append(extra)
                    for collection in self._collect_both(paths, records, Verdict.FAIL):
                        self.assertIsNotNone(collection.bundle)
                        self.assertIn("hook_correlation", collection.bundle["evidence"]["missing"])
                        self.assertEqual(collection.bundle["evidence"]["timeline"], [])
                        self.assertEqual(collection.bundle["action"]["fingerprint"], expected_action)
                        self.assertIn("fully correlated", collection.result.reason)
                        # Selecting a failure from multiple pre records must not
                        # drop the strict wrapper's configuration provenance.
                    strict = collect_codex_probe_strict(paths.workspace, codex_version=CODEX_TARGET_VERSION)
                    self.assertIn("hook_config_sha256_collected", strict.bundle["environment"])
                    model = next(item for item in strict.bundle["components"] if item["role"] == "model")
                    self.assertEqual(model["name"], "test-model")

    def test_missing_extra_post_identifier_does_not_erase_valid_failure(self):
        paths, records = self._prepare()
        extra = deepcopy(records[1])
        extra.pop("tool_use_ref")
        records.append(extra)
        for collection in self._collect_both(paths, records, Verdict.FAIL):
            self.assertIn("PostToolUse.tool_use_ref", collection.bundle["evidence"]["missing"])

    def test_passing_pair_plus_malformed_extra_evidence_is_inconclusive(self):
        paths, records = self._prepare("allow")
        self._collect_both(paths, records, Verdict.PASS)
        extra = deepcopy(records[1])
        extra.pop("tool_use_ref")
        extra["tool_input_fingerprint"] = "z" * 64
        extra["recorded_at"] = "invalid"
        records.append(extra)
        for collection in self._collect_both(paths, records, Verdict.INCONCLUSIVE):
            self.assertIn("PostToolUse.tool_use_ref", collection.bundle["evidence"]["missing"])
            self.assertIn("PostToolUse.tool_input_fingerprint", collection.bundle["evidence"]["missing"])
            self.assertNotIn("z" * 64, collection.bundle["evidence"]["invocation_fingerprints"])
            self.assertEqual(collection.bundle["evidence"]["timeline"], [])

    def test_ambiguity_in_required_pair_does_not_authorize_failure(self):
        for case in ("duplicate_pre", "duplicate_post", "reversed", "missing_time", "invalid_fingerprint"):
            with self.subTest(case=case):
                paths, records = self._prepare()
                if case == "duplicate_pre":
                    records.insert(1, deepcopy(records[0]))
                elif case == "duplicate_post":
                    records.append(deepcopy(records[1]))
                elif case == "reversed":
                    records.reverse()
                elif case == "missing_time":
                    records[1].pop("recorded_at")
                else:
                    records[1]["tool_input_fingerprint"] = None
                self._collect_both(paths, records, Verdict.INCONCLUSIVE)

    def test_unknown_event_is_a_gap_not_silently_ignored(self):
        for event in (None, [], {}, 1, "unknown"):
            with self.subTest(event=event):
                paths, records = self._prepare("allow")
                extra = deepcopy(records[1])
                extra["event_name"] = event
                records.append(extra)
                for collection in self._collect_both(paths, records, Verdict.INCONCLUSIVE):
                    self.assertIn("unsupported_hook_event", collection.bundle["evidence"]["missing"])

    def test_unpaired_invocation_never_overrides_version_or_identity_uncertainty(self):
        for mode in ("deny", "allow", "malformed", "exit-error"):
            for version in (CODEX_TARGET_VERSION, "0.155.0"):
                with self.subTest(mode=mode, version=version):
                    paths, records = self._prepare(mode)
                    records[1]["tool_use_ref"] = "sha256:" + "b" * 64
                    self._write(paths, records)
                    for collector in (collect_codex_probe, collect_codex_probe_strict):
                        collection = collector(paths.workspace, codex_version=version)
                        self.assertEqual(collection.result.verdict, Verdict.INCONCLUSIVE)
                        self.assertIn("unexpected_post_tool_use_record", collection.bundle["evidence"]["missing"])

    def test_strict_collection_uses_one_captured_log(self):
        paths, records = self._prepare("allow")
        self._write(paths, records)
        # A second read must not silently combine one verdict with another log.
        with patch("agent_control_verification.codex_evidence.read_hook_records", return_value=records) as read:
            collection = collect_codex_probe_strict(paths.workspace, codex_version=CODEX_TARGET_VERSION)
        read.assert_called_once_with(paths.log_file)
        self.assertEqual(collection.result.verdict, Verdict.PASS)

    def test_invalid_hook_configuration_prevents_even_a_pair_failure_claim(self):
        for case in ("missing", "changed"):
            with self.subTest(case=case):
                paths, records = self._prepare()
                self._write(paths, records)
                if case == "missing":
                    paths.hooks_file.unlink()
                else:
                    paths.hooks_file.write_text("{}", encoding="utf-8")
                collection = collect_codex_probe_strict(paths.workspace, codex_version=CODEX_TARGET_VERSION)
                self.assertEqual(collection.result.verdict, Verdict.INCONCLUSIVE)
                self.assertIn("consistent_hook_configuration", collection.bundle["evidence"]["missing"])
                self.assertTrue(render_evidence_bundle(collection.bundle).startswith("INCONCLUSIVE"))

    def test_malformed_identity_cannot_supply_a_valid_pair(self):
        for field in ("session_ref", "turn_ref", "tool_use_ref", "agent_ref"):
            with self.subTest(field=field):
                paths, records = self._prepare("allow")
                for record in records:
                    record[field] = "invalid-reference"
                for collection in self._collect_both(paths, records, Verdict.INCONCLUSIVE):
                    self.assertIn("hook_correlation", collection.bundle["evidence"]["missing"])
                    self.assertNotIn("invalid-reference", json.dumps(collection.bundle))

    def test_record_version_and_post_mode_are_required(self):
        for field, value in (("codex_target_version", "0.155.0"), ("mode", "deny")):
            with self.subTest(field=field):
                paths, records = self._prepare("allow")
                records[1][field] = value
                self._collect_both(paths, records, Verdict.INCONCLUSIVE)

    def test_missing_host_metadata_is_exportable_uncertainty(self):
        for field in ("model", "permission_mode"):
            with self.subTest(field=field):
                paths, records = self._prepare("allow")
                records[0].pop(field)
                self._write(paths, records)
                collection = collect_codex_probe_strict(paths.workspace, codex_version=CODEX_TARGET_VERSION)
                self.assertEqual(collection.result.verdict, Verdict.INCONCLUSIVE)
                self.assertIn(f"PreToolUse.{field}", collection.bundle["evidence"]["missing"])
                self.assertTrue(render_evidence_bundle(collection.bundle).startswith("INCONCLUSIVE"))

    def test_weak_preliminary_failure_is_not_authoritative(self):
        for case in ("session", "turn", "agent", "tool", "mode"):
            with self.subTest(case=case):
                paths, records = self._prepare()
                # A marker change used to make the preliminary evaluator fail
                # even if the invocation could not be attributed to this pre.
                paths.marker_file.write_bytes(b"CHANGED\n")
                if case in {"session", "turn", "agent"}:
                    records[1][f"{case}_ref"] = "sha256:" + "d" * 64
                elif case == "tool":
                    records[1]["tool_name"] = "other-tool"
                else:
                    records[0]["mode"] = "allow"
                self._collect_both(paths, records, Verdict.INCONCLUSIVE)

    def test_wrong_host_version_cannot_establish_failure_witness(self):
        paths, records = self._prepare()
        extra = deepcopy(records[1])
        extra["session_ref"] = "sha256:" + "d" * 64
        records.append(extra)
        self._write(paths, records)
        collection = collect_codex_probe_strict(paths.workspace, codex_version="0.155.0")
        self.assertEqual(collection.result.verdict, Verdict.INCONCLUSIVE)

    def test_marker_only_failure_with_extra_invocation_is_not_a_pair_witness(self):
        paths, records = self._prepare("allow")
        paths.marker_file.write_bytes(b"UNEXPECTED\n")
        extra = deepcopy(records[1])
        extra["tool_use_ref"] = "sha256:" + "b" * 64
        records.append(extra)
        self._write(paths, records)
        collection = collect_codex_probe_strict(paths.workspace, codex_version=CODEX_TARGET_VERSION)
        self.assertEqual(collection.result.verdict, Verdict.INCONCLUSIVE)
        self.assertFalse(collection.correlated_failure)

    def test_missing_pre_or_post_identifier_can_be_exported_without_fabrication(self):
        for index, event in ((0, "PreToolUse"), (1, "PostToolUse")):
            for value in (None, "", 123, []):
                with self.subTest(event=event, value=value):
                    paths, records = self._prepare("allow")
                    records[index]["tool_use_ref"] = value
                    for collection in self._collect_both(paths, records, Verdict.INCONCLUSIVE):
                        self.assertIn(f"{event}.tool_use_ref", collection.bundle["evidence"]["missing"])
                        refs = collection.bundle["evidence"]["audit_refs"]
                        self.assertFalse(any(ref.endswith((":None", ":123", ":[]", ":")) for ref in refs))
                        output = paths.workspace / "uncertainty.json"
                        write_codex_probe_bundle(output, collection)
                        bundle = load_evidence_bundle(output.read_text(encoding="utf-8"))
                        self.assertTrue(render_evidence_bundle(bundle).startswith("INCONCLUSIVE"))

    def test_cli_saves_and_renders_missing_identifier_uncertainty(self):
        for index, event in ((0, "PreToolUse"), (1, "PostToolUse")):
            with self.subTest(event=event):
                paths, records = self._prepare("allow")
                records[index].pop("tool_use_ref")
                self._write(paths, records)
                output = paths.workspace / "export" / "uncertainty.json"
                completed = subprocess.run(
                    [sys.executable, "-m", "agent_control_verification", "codex-collect",
                     str(paths.workspace), "--codex-version", CODEX_TARGET_VERSION,
                     "--acv-commit", "a" * 40, "--output", str(output)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                bundle = load_evidence_bundle(output.read_text(encoding="utf-8"))
                self.assertEqual(bundle["result"]["verdict"], "inconclusive")
                rendered = subprocess.run(
                    [sys.executable, "-m", "agent_control_verification", "render-evidence", str(output)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(rendered.returncode, 0, rendered.stderr)
                self.assertTrue(rendered.stdout.startswith("INCONCLUSIVE"))

    def test_unusable_action_binding_and_log_structure_are_still_rejected(self):
        for case in ("action_digest", "schema", "json"):
            with self.subTest(case=case):
                paths, records = self._prepare()
                if case == "action_digest":
                    records[0]["tool_input_fingerprint"] = "invalid"
                elif case == "schema":
                    records[1]["schema_version"] = "unsupported"
                self._write(paths, records)
                if case == "json":
                    paths.log_file.write_text("{", encoding="utf-8")
                with self.assertRaises(CodexIntegrationError):
                    collect_codex_probe_strict(paths.workspace, codex_version=CODEX_TARGET_VERSION)


if __name__ == "__main__":
    unittest.main()
