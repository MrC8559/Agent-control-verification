import unittest

from agent_control_verification.model import Action, ControlDecision, DecisionRecord, Verdict
from agent_control_verification.observer import observe_run
from agent_control_verification.sandbox import SyntheticSandbox
from agent_control_verification.targets import (
    DenyButExecutesTarget,
    HardenedDemoTarget,
    MissingAuditTarget,
    MutateAfterAllowTarget,
)
from agent_control_verification.verifier import (
    verify_allow_binds_exact_action,
    verify_consequential_effect_is_audited,
    verify_deny_prevents_effect,
)


class DenyPreventsEffectTests(unittest.TestCase):
    def setUp(self):
        self.action = Action(
            action_id="deny-1",
            tool="file.write",
            target="/protected/config.txt",
            arguments={"content": "blocked"},
        )

    def test_hardened_target_passes(self):
        observation = observe_run(HardenedDemoTarget(), self.action)
        result = verify_deny_prevents_effect(observation)
        self.assertEqual(result.verdict, Verdict.PASS)

    def test_deny_that_still_executes_fails(self):
        sandbox = SyntheticSandbox()
        observation = observe_run(DenyButExecutesTarget(), self.action, sandbox)
        result = verify_deny_prevents_effect(observation)

        self.assertEqual(result.verdict, Verdict.FAIL)
        self.assertEqual(sandbox.files["/protected/config.txt"], "blocked")


class AllowBindingTests(unittest.TestCase):
    def test_hardened_exact_action_passes(self):
        action = Action(
            action_id="allow-1",
            tool="file.write",
            target="/tmp/approved.txt",
            arguments={"content": "approved"},
        )
        observation = observe_run(HardenedDemoTarget(), action)
        result = verify_allow_binds_exact_action(observation)
        self.assertEqual(result.verdict, Verdict.PASS)

    def test_mutation_after_allow_fails(self):
        action = Action(
            action_id="allow-2",
            tool="file.write",
            target="/tmp/approved.txt",
            arguments={"content": "approved"},
        )
        observation = observe_run(MutateAfterAllowTarget(), action)
        result = verify_allow_binds_exact_action(observation)
        self.assertEqual(result.verdict, Verdict.FAIL)


class AuditTests(unittest.TestCase):
    def test_hardened_effect_has_matching_audit(self):
        action = Action(
            action_id="audit-1",
            tool="email.send",
            target="synthetic@example.invalid",
            arguments={"subject": "test", "body": "local"},
        )
        observation = observe_run(HardenedDemoTarget(), action)
        result = verify_consequential_effect_is_audited(observation)
        self.assertEqual(result.verdict, Verdict.PASS)

    def test_missing_audit_fails(self):
        action = Action(
            action_id="audit-2",
            tool="email.send",
            target="synthetic@example.invalid",
            arguments={"subject": "test", "body": "local"},
        )
        observation = observe_run(MissingAuditTarget(), action)
        result = verify_consequential_effect_is_audited(observation)
        self.assertEqual(result.verdict, Verdict.FAIL)


class InconclusiveTests(unittest.TestCase):
    def test_allow_property_is_inconclusive_without_effect(self):
        action = Action(
            action_id="unknown-1",
            tool="http.post",
            target="https://example.invalid",
            arguments={"json": {"synthetic": True}},
        )
        decision = DecisionRecord(
            decision=ControlDecision.ALLOW,
            action_id=action.action_id,
            approved_fingerprint=action.fingerprint(),
        )
        from agent_control_verification.model import Observation

        observation = Observation(
            requested_action=action,
            decision=decision,
            effects=(),
            audit_events=(),
        )
        result = verify_allow_binds_exact_action(observation)
        self.assertEqual(result.verdict, Verdict.INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()
