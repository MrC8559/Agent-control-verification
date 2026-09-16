from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from agent_control_verification.evidence import (
    ComponentVersion,
    EvidenceEvent,
    EvidenceValidationError,
    build_evidence_bundle,
    evidence_bundle_json,
    load_evidence_bundle,
    render_evidence_bundle,
    sha256_text,
    validate_evidence_bundle,
)
from agent_control_verification.evidence_demo import build_demo_evidence_bundle
from agent_control_verification.model import ControlDecision, Verdict, VerificationResult


T0 = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)


class EvidenceBundleTests(unittest.TestCase):
    def _bundle(self):
        result = VerificationResult(
            property_name="deny_prevents_effect",
            verdict=Verdict.FAIL,
            reason="an effect occurred for an action the control denied",
            evidence={},
        )
        return build_evidence_bundle(
            bundle_id="test-bundle-1",
            created_at=T0,
            acv_version="0.0.3",
            acv_commit="abc123",
            scenario_id="test.scenario",
            result=result,
            action_fingerprint=sha256_text("semantic-action"),
            control_decision=ControlDecision.DENY,
            control_reason_code="policy_denied",
            control_reason_digest=sha256_text("synthetic reason"),
            components=(
                ComponentVersion("target", "fixture", "1", None),
                ComponentVersion("host", "test-host", "1", "def456"),
            ),
            invocation_fingerprints=(sha256_text("invocation"),),
            effect_fingerprints=(sha256_text("effect"),),
            audit_refs=("audit:1",),
            missing_evidence=("independent_control_trace",),
            timeline=(
                EvidenceEvent(0, "decision", "decision:1", T0),
                EvidenceEvent(1, "effect", "effect:1", T0),
            ),
            environment={"python": "3.13.7", "platform": "linux"},
            redactions=("action.arguments",),
            canary_ids=("canary-1",),
        )

    def test_round_trip_validates_and_preserves_verdict(self):
        bundle = self._bundle()
        text = evidence_bundle_json(bundle)
        loaded = load_evidence_bundle(text)
        self.assertEqual(loaded["result"]["verdict"], "fail")
        self.assertEqual(loaded["scenario"]["property"], "deny_prevents_effect")

    def test_integrity_digest_detects_tampering(self):
        bundle = deepcopy(self._bundle())
        bundle["result"]["verdict"] = "pass"
        with self.assertRaises(EvidenceValidationError):
            validate_evidence_bundle(bundle)

    def test_raw_payloads_cannot_be_marked_as_included(self):
        bundle = deepcopy(self._bundle())
        bundle["privacy"]["raw_payloads_included"] = True
        with self.assertRaises(EvidenceValidationError):
            validate_evidence_bundle(bundle)

    def test_missing_evidence_is_explicit_and_rendered(self):
        bundle = self._bundle()
        rendered = render_evidence_bundle(bundle)
        self.assertIn("Missing evidence: independent_control_trace", rendered)
        self.assertIn("FAIL deny_prevents_effect", rendered)

    def test_unknown_top_level_fields_are_rejected(self):
        bundle = deepcopy(self._bundle())
        bundle["raw_prompt"] = "do not allow this field"
        with self.assertRaises(EvidenceValidationError):
            validate_evidence_bundle(bundle)

    def test_timeline_sequence_must_be_contiguous(self):
        bundle = deepcopy(self._bundle())
        bundle["evidence"]["timeline"][1]["sequence"] = 3
        bundle["integrity"]["digest"] = "0" * 64
        with self.assertRaises(EvidenceValidationError):
            validate_evidence_bundle(bundle)

    def test_demo_bundle_contains_no_raw_action_payload(self):
        bundle = build_demo_evidence_bundle(created_at=T0, acv_commit="demo-commit")
        text = evidence_bundle_json(bundle)
        self.assertNotIn("synthetic demo value", text)
        self.assertNotIn("/protected/config.txt", text)
        self.assertEqual(bundle["privacy"]["raw_payloads_included"], False)
        self.assertEqual(bundle["result"]["verdict"], "fail")

    def test_demo_bundle_can_be_saved_loaded_and_rendered_independently(self):
        bundle = build_demo_evidence_bundle(created_at=T0, acv_commit="demo-commit")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            path.write_text(evidence_bundle_json(bundle), encoding="utf-8")
            loaded = load_evidence_bundle(path.read_text(encoding="utf-8"))
            rendered = render_evidence_bundle(loaded)
        self.assertIn("demo.deny-but-executes", rendered)
        self.assertIn("Control decision: deny", rendered)
        self.assertIn("Effect evidence: 1", rendered)

    def test_schema_file_is_valid_json_with_matching_version(self):
        schema_path = Path(__file__).parents[1] / "schemas" / "evidence-bundle.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(schema["$id"], "urn:acv:evidence-bundle:0.1")
        self.assertEqual(
            schema["properties"]["schema_version"]["const"],
            "acv-evidence-0.1",
        )


if __name__ == "__main__":
    unittest.main()
