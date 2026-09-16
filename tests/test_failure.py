import unittest

from agent_control_verification.failure import (
    ControlCause,
    ControlFailureObservation,
    FailurePosture,
    SyntheticHostBehavior,
    simulate_control_failure,
    verify_control_failure_does_not_silently_execute,
)
from agent_control_verification.model import Action, Verdict


class FailurePostureTests(unittest.TestCase):
    def setUp(self):
        self.action = Action(
            action_id="failure-1",
            tool="file.write",
            target="protected/config.txt",
            arguments={"content": "synthetic"},
        )

    def _verify(self, cause, posture, behavior):
        observation = simulate_control_failure(
            self.action,
            cause=cause,
            configured_posture=posture,
            host_behavior=behavior,
        )
        return verify_control_failure_does_not_silently_execute(observation)

    def test_policy_deny_without_invocation_passes(self):
        result = self._verify(
            ControlCause.POLICY_DENY,
            FailurePosture.DENY,
            SyntheticHostBehavior.BLOCK,
        )
        self.assertEqual(result.verdict, Verdict.PASS)

    def test_policy_deny_followed_by_effect_fails(self):
        result = self._verify(
            ControlCause.POLICY_DENY,
            FailurePosture.DENY,
            SyntheticHostBehavior.PROCEED_EFFECT,
        )
        self.assertEqual(result.verdict, Verdict.FAIL)

    def test_security_refusal_is_not_converted_to_fail_open_permission(self):
        result = self._verify(
            ControlCause.SECURITY_REFUSAL,
            FailurePosture.PROCEED,
            SyntheticHostBehavior.BLOCK,
        )
        self.assertEqual(result.verdict, Verdict.PASS)

    def test_security_refusal_followed_by_effect_fails_even_if_posture_is_proceed(self):
        result = self._verify(
            ControlCause.SECURITY_REFUSAL,
            FailurePosture.PROCEED,
            SyntheticHostBehavior.PROCEED_EFFECT,
        )
        self.assertEqual(result.verdict, Verdict.FAIL)

    def test_timeout_fail_closed_without_effect_passes(self):
        result = self._verify(
            ControlCause.TIMEOUT,
            FailurePosture.DENY,
            SyntheticHostBehavior.BLOCK,
        )
        self.assertEqual(result.verdict, Verdict.PASS)

    def test_timeout_fail_open_effect_is_not_a_pass(self):
        result = self._verify(
            ControlCause.TIMEOUT,
            FailurePosture.PROCEED,
            SyntheticHostBehavior.PROCEED_EFFECT,
        )
        self.assertEqual(result.verdict, Verdict.FAIL)
        self.assertEqual(result.evidence["configured_posture"], "proceed")
        self.assertEqual(result.evidence["cause"], "timeout")

    def test_transport_failure_fail_open_effect_fails(self):
        result = self._verify(
            ControlCause.TRANSPORT_UNAVAILABLE,
            FailurePosture.PROCEED,
            SyntheticHostBehavior.PROCEED_EFFECT,
        )
        self.assertEqual(result.verdict, Verdict.FAIL)

    def test_malformed_response_fail_closed_passes(self):
        result = self._verify(
            ControlCause.MALFORMED_RESPONSE,
            FailurePosture.DENY,
            SyntheticHostBehavior.BLOCK,
        )
        self.assertEqual(result.verdict, Verdict.PASS)

    def test_malformed_response_fail_open_effect_fails(self):
        result = self._verify(
            ControlCause.MALFORMED_RESPONSE,
            FailurePosture.PROCEED,
            SyntheticHostBehavior.PROCEED_EFFECT,
        )
        self.assertEqual(result.verdict, Verdict.FAIL)

    def test_fail_open_invocation_without_effect_still_fails(self):
        result = self._verify(
            ControlCause.TIMEOUT,
            FailurePosture.PROCEED,
            SyntheticHostBehavior.PROCEED_NO_EFFECT,
        )
        self.assertEqual(result.verdict, Verdict.FAIL)

    def test_unknown_invocation_and_effect_are_inconclusive(self):
        result = self._verify(
            ControlCause.TRANSPORT_UNAVAILABLE,
            FailurePosture.PROCEED,
            SyntheticHostBehavior.UNKNOWN,
        )
        self.assertEqual(result.verdict, Verdict.INCONCLUSIVE)

    def test_unknown_effect_is_inconclusive(self):
        observation = ControlFailureObservation(
            action=self.action,
            cause=ControlCause.TIMEOUT,
            configured_posture=FailurePosture.DENY,
            execution_attempted=False,
            effect_observed=None,
            reason="effect observer unavailable",
        )
        result = verify_control_failure_does_not_silently_execute(observation)
        self.assertEqual(result.verdict, Verdict.INCONCLUSIVE)

    def test_contradictory_effect_evidence_is_inconclusive(self):
        observation = ControlFailureObservation(
            action=self.action,
            cause=ControlCause.MALFORMED_RESPONSE,
            configured_posture=FailurePosture.DENY,
            execution_attempted=False,
            effect_observed=True,
            reason="contradictory fixture",
        )
        result = verify_control_failure_does_not_silently_execute(observation)
        self.assertEqual(result.verdict, Verdict.INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()
