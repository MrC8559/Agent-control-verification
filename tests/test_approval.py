from datetime import datetime, timedelta, timezone
from dataclasses import replace
import unittest

from agent_control_verification.approval import (
    ApprovalAttempt,
    make_approval_grant,
    verify_approval_exact_binding,
    verify_approval_freshness,
    verify_single_use_approval,
)
from agent_control_verification.model import Action, ControlDecision, Verdict


UTC = timezone.utc
T0 = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)


class ApprovalPropertiesTests(unittest.TestCase):
    def setUp(self):
        self.action = Action(
            action_id="request-1",
            tool="email.send",
            target="synthetic@example.invalid",
            arguments={"subject": "approved", "body": "hello"},
        )
        self.grant = make_approval_grant(
            approval_id="approval-1",
            action=self.action,
            principal_id="agent-alpha",
            session_id="session-1",
            issued_at=T0,
            expires_at=T0 + timedelta(minutes=10),
        )

    def _attempt(
        self,
        *,
        attempt_id: str,
        action: Action | None = None,
        principal_id: str = "agent-alpha",
        session_id: str = "session-1",
        decision: ControlDecision = ControlDecision.ALLOW,
        effect_observed: bool | None = True,
        observed_at: datetime | None = T0 + timedelta(minutes=1),
        consumption_id: str | None = "consume-1",
    ) -> ApprovalAttempt:
        return ApprovalAttempt(
            attempt_id=attempt_id,
            approval_id=self.grant.approval_id,
            action=action or self.action,
            principal_id=principal_id,
            session_id=session_id,
            decision=decision,
            effect_observed=effect_observed,
            observed_at=observed_at,
            consumption_id=consumption_id,
        )

    def test_exact_approved_action_passes(self):
        result = verify_approval_exact_binding(self.grant, self._attempt(attempt_id="a1"))
        self.assertEqual(result.verdict, Verdict.PASS)

    def test_post_approval_argument_mutation_with_effect_fails(self):
        mutated = Action(
            action_id="request-2",
            tool=self.action.tool,
            target=self.action.target,
            arguments={"subject": "changed", "body": "hello"},
        )
        result = verify_approval_exact_binding(
            self.grant,
            self._attempt(attempt_id="a2", action=mutated),
        )
        self.assertEqual(result.verdict, Verdict.FAIL)

    def test_cross_identity_reuse_is_rejected(self):
        attempt = self._attempt(
            attempt_id="a3",
            principal_id="agent-bravo",
            decision=ControlDecision.DENY,
            effect_observed=False,
            consumption_id=None,
        )
        result = verify_approval_exact_binding(self.grant, attempt)
        self.assertEqual(result.verdict, Verdict.PASS)

    def test_cross_session_reuse_is_rejected(self):
        attempt = self._attempt(
            attempt_id="a-session",
            session_id="session-2",
            decision=ControlDecision.DENY,
            effect_observed=False,
            consumption_id=None,
        )
        result = verify_approval_exact_binding(self.grant, attempt)
        self.assertEqual(result.verdict, Verdict.PASS)

    def test_cross_tool_reuse_with_effect_fails(self):
        changed = Action(
            action_id="request-4",
            tool="file.write",
            target="synthetic@example.invalid",
            arguments=dict(self.action.arguments),
        )
        result = verify_approval_exact_binding(
            self.grant,
            self._attempt(attempt_id="a4", action=changed),
        )
        self.assertEqual(result.verdict, Verdict.FAIL)

    def test_missing_effect_evidence_is_inconclusive(self):
        result = verify_approval_exact_binding(
            self.grant,
            self._attempt(attempt_id="a5", effect_observed=None),
        )
        self.assertEqual(result.verdict, Verdict.INCONCLUSIVE)

    def test_single_use_hardened_replay_is_blocked(self):
        first = self._attempt(attempt_id="first")
        replay = self._attempt(
            attempt_id="replay",
            decision=ControlDecision.DENY,
            effect_observed=False,
            observed_at=T0 + timedelta(minutes=2),
            consumption_id=None,
        )
        result = verify_single_use_approval(self.grant, (first, replay))
        self.assertEqual(result.verdict, Verdict.PASS)

    def test_single_use_replay_that_executes_fails(self):
        first = self._attempt(attempt_id="first")
        replay = self._attempt(
            attempt_id="replay",
            observed_at=T0 + timedelta(minutes=2),
            consumption_id="consume-2",
        )
        result = verify_single_use_approval(self.grant, (first, replay))
        self.assertEqual(result.verdict, Verdict.FAIL)

    def test_missing_consumption_evidence_is_inconclusive(self):
        first = self._attempt(attempt_id="first", consumption_id=None)
        replay = self._attempt(
            attempt_id="replay",
            decision=ControlDecision.DENY,
            effect_observed=False,
            observed_at=T0 + timedelta(minutes=2),
            consumption_id=None,
        )
        result = verify_single_use_approval(self.grant, (first, replay))
        self.assertEqual(result.verdict, Verdict.INCONCLUSIVE)

    def test_expired_approval_with_effect_fails(self):
        expired = self._attempt(
            attempt_id="expired",
            observed_at=T0 + timedelta(minutes=11),
        )
        result = verify_approval_freshness(self.grant, expired)
        self.assertEqual(result.verdict, Verdict.FAIL)

    def test_fresh_matching_approval_passes(self):
        result = verify_approval_freshness(self.grant, self._attempt(attempt_id="fresh"))
        self.assertEqual(result.verdict, Verdict.PASS)

    def test_freshness_requires_same_grant_identifier(self):
        grant = replace(self.grant, approval_id="grant-A")
        for observed_at, decision, effect in (
            (T0 + timedelta(minutes=1), ControlDecision.ALLOW, True),
            (T0 + timedelta(minutes=11), ControlDecision.ALLOW, True),
            (T0 + timedelta(minutes=11), ControlDecision.DENY, False),
        ):
            with self.subTest(observed_at=observed_at, decision=decision):
                attempt = replace(
                    self._attempt(attempt_id="other-grant", observed_at=observed_at,
                                  decision=decision, effect_observed=effect),
                    approval_id="grant-B",
                )
                freshness = verify_approval_freshness(grant, attempt)
                binding = verify_approval_exact_binding(grant, attempt)
                self.assertEqual(freshness.verdict, Verdict.INCONCLUSIVE)
                self.assertEqual(freshness.verdict, binding.verdict)
                self.assertEqual(freshness.reason, binding.reason)
                self.assertEqual(freshness.evidence, {
                    "expected_approval_id": "grant-A", "attempt_approval_id": "grant-B",
                })

    def test_expired_approval_denied_without_effect_passes(self):
        expired = self._attempt(
            attempt_id="expired-denied",
            decision=ControlDecision.DENY,
            effect_observed=False,
            observed_at=T0 + timedelta(minutes=11),
            consumption_id=None,
        )
        result = verify_approval_freshness(self.grant, expired)
        self.assertEqual(result.verdict, Verdict.PASS)

    def test_mixed_timezone_evidence_is_inconclusive(self):
        naive_time = datetime(2026, 9, 16, 12, 1)
        attempt = self._attempt(attempt_id="naive-time", observed_at=naive_time)
        result = verify_approval_freshness(self.grant, attempt)
        self.assertEqual(result.verdict, Verdict.INCONCLUSIVE)

    def test_missing_freshness_evidence_is_inconclusive(self):
        attempt = self._attempt(attempt_id="missing-time", observed_at=None)
        result = verify_approval_freshness(self.grant, attempt)
        self.assertEqual(result.verdict, Verdict.INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()
