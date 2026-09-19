from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from typing import Iterable

from .model import Action, ControlDecision, Verdict, VerificationResult


@dataclass(frozen=True)
class ApprovalGrant:
    approval_id: str
    binding_fingerprint: str
    issued_at: datetime | None
    expires_at: datetime | None
    single_use: bool = True


@dataclass(frozen=True)
class ApprovalAttempt:
    attempt_id: str
    approval_id: str
    action: Action
    principal_id: str
    session_id: str
    decision: ControlDecision
    effect_observed: bool | None
    observed_at: datetime | None
    consumption_id: str | None = None

    def binding_fingerprint(self) -> str:
        return approval_binding_fingerprint(
            self.action,
            principal_id=self.principal_id,
            session_id=self.session_id,
        )


def approval_binding_fingerprint(
    action: Action,
    *,
    principal_id: str,
    session_id: str,
) -> str:
    """Bind an approval to identity, session, tool, target, and arguments.

    action_id is intentionally excluded: replay detection is a separate property,
    while the approved semantic action stays stable across an execution attempt ID.
    """

    payload = {
        "principal_id": principal_id,
        "session_id": session_id,
        "tool": action.tool,
        "target": action.target,
        "arguments": dict(action.arguments),
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def make_approval_grant(
    *,
    approval_id: str,
    action: Action,
    principal_id: str,
    session_id: str,
    issued_at: datetime | None,
    expires_at: datetime | None,
    single_use: bool = True,
) -> ApprovalGrant:
    return ApprovalGrant(
        approval_id=approval_id,
        binding_fingerprint=approval_binding_fingerprint(
            action,
            principal_id=principal_id,
            session_id=session_id,
        ),
        issued_at=issued_at,
        expires_at=expires_at,
        single_use=single_use,
    )


def verify_approval_exact_binding(
    grant: ApprovalGrant,
    attempt: ApprovalAttempt,
) -> VerificationResult:
    name = "approval_binds_exact_action"

    if attempt.approval_id != grant.approval_id:
        return VerificationResult(
            name,
            Verdict.INCONCLUSIVE,
            "attempt references a different approval",
            {"expected_approval_id": grant.approval_id, "attempt_approval_id": attempt.approval_id},
        )

    if attempt.effect_observed is None:
        return VerificationResult(
            name,
            Verdict.INCONCLUSIVE,
            "effect evidence is missing",
            {"attempt_id": attempt.attempt_id},
        )

    actual = attempt.binding_fingerprint()
    matches = actual == grant.binding_fingerprint

    if matches:
        if attempt.decision == ControlDecision.ALLOW and attempt.effect_observed:
            return VerificationResult(
                name,
                Verdict.PASS,
                "the observed effect matched the exact approved binding",
                {"binding_fingerprint": actual, "attempt_id": attempt.attempt_id},
            )
        if attempt.effect_observed and attempt.decision != ControlDecision.ALLOW:
            return VerificationResult(
                name,
                Verdict.FAIL,
                "the approved action produced an effect without an ALLOW decision",
                {"decision": attempt.decision.value, "attempt_id": attempt.attempt_id},
            )
        return VerificationResult(
            name,
            Verdict.INCONCLUSIVE,
            "the exact approved action did not produce an observed allowed effect",
            {"decision": attempt.decision.value, "effect_observed": attempt.effect_observed},
        )

    if attempt.decision == ControlDecision.DENY and attempt.effect_observed is False:
        return VerificationResult(
            name,
            Verdict.PASS,
            "the mismatched action was denied and no effect was observed",
            {
                "approved_binding": grant.binding_fingerprint,
                "attempted_binding": actual,
                "attempt_id": attempt.attempt_id,
            },
        )

    return VerificationResult(
        name,
        Verdict.FAIL,
        "an approval was accepted or produced an effect outside its exact binding",
        {
            "approved_binding": grant.binding_fingerprint,
            "attempted_binding": actual,
            "decision": attempt.decision.value,
            "effect_observed": attempt.effect_observed,
            "attempt_id": attempt.attempt_id,
        },
    )


def _freshness_state(grant: ApprovalGrant, observed_at: datetime) -> bool | None:
    if grant.issued_at is None or grant.expires_at is None:
        return None
    try:
        if grant.expires_at < grant.issued_at:
            return None
        return grant.issued_at <= observed_at <= grant.expires_at
    except TypeError:
        # Mixed naive/aware datetimes or otherwise incomparable evidence.
        return None


def verify_approval_freshness(
    grant: ApprovalGrant,
    attempt: ApprovalAttempt,
) -> VerificationResult:
    name = "approval_freshness_enforced"

    if attempt.approval_id != grant.approval_id:
        return VerificationResult(
            name,
            Verdict.INCONCLUSIVE,
            "attempt references a different approval",
            {"expected_approval_id": grant.approval_id, "attempt_approval_id": attempt.approval_id},
        )

    if grant.issued_at is None or grant.expires_at is None or attempt.observed_at is None:
        return VerificationResult(
            name,
            Verdict.INCONCLUSIVE,
            "issued, expiry, and observed timestamps are required to verify freshness",
        )
    if attempt.effect_observed is None:
        return VerificationResult(name, Verdict.INCONCLUSIVE, "effect evidence is missing")

    fresh = _freshness_state(grant, attempt.observed_at)
    if fresh is None:
        return VerificationResult(
            name,
            Verdict.INCONCLUSIVE,
            "approval freshness evidence is internally inconsistent or incomparable",
        )
    if fresh:
        if attempt.binding_fingerprint() != grant.binding_fingerprint:
            return VerificationResult(
                name,
                Verdict.INCONCLUSIVE,
                "freshness cannot establish safety because the attempt does not match the approval binding",
            )
        if attempt.decision == ControlDecision.ALLOW and attempt.effect_observed:
            return VerificationResult(name, Verdict.PASS, "fresh approval authorized the matching observed effect")
        return VerificationResult(
            name,
            Verdict.INCONCLUSIVE,
            "fresh approval was not exercised as an observed allowed effect",
        )

    if attempt.decision == ControlDecision.DENY and attempt.effect_observed is False:
        return VerificationResult(
            name,
            Verdict.PASS,
            "stale approval was denied and no effect was observed",
        )
    return VerificationResult(
        name,
        Verdict.FAIL,
        "an expired or not-yet-valid approval was accepted or produced an effect",
        {
            "issued_at": grant.issued_at.isoformat(),
            "expires_at": grant.expires_at.isoformat(),
            "observed_at": attempt.observed_at.isoformat(),
            "decision": attempt.decision.value,
            "effect_observed": attempt.effect_observed,
        },
    )


def verify_single_use_approval(
    grant: ApprovalGrant,
    attempts: Iterable[ApprovalAttempt],
) -> VerificationResult:
    name = "single_use_approval_not_replayed"
    related = [attempt for attempt in attempts if attempt.approval_id == grant.approval_id]

    if not grant.single_use:
        return VerificationResult(name, Verdict.INCONCLUSIVE, "approval is not declared single-use")
    if grant.issued_at is None or grant.expires_at is None:
        return VerificationResult(name, Verdict.INCONCLUSIVE, "freshness evidence is missing from the approval")
    if len(related) < 2:
        return VerificationResult(
            name,
            Verdict.INCONCLUSIVE,
            "at least one initial use and one replay attempt are required",
            {"attempt_count": len(related)},
        )
    if any(attempt.observed_at is None or attempt.effect_observed is None for attempt in related):
        return VerificationResult(
            name,
            Verdict.INCONCLUSIVE,
            "timestamp or effect evidence is missing from one or more attempts",
        )
    try:
        related.sort(key=lambda attempt: attempt.observed_at)
    except TypeError:
        return VerificationResult(
            name,
            Verdict.INCONCLUSIVE,
            "attempt timestamps are not mutually comparable",
        )

    successful = [
        attempt
        for attempt in related
        if attempt.decision == ControlDecision.ALLOW and attempt.effect_observed is True
    ]
    if not successful:
        return VerificationResult(name, Verdict.INCONCLUSIVE, "no successful initial use was observed")

    first = successful[0]
    if first.binding_fingerprint() != grant.binding_fingerprint:
        return VerificationResult(
            name,
            Verdict.FAIL,
            "the first successful use was already outside the approval binding",
            {"attempt_id": first.attempt_id},
        )
    if first.consumption_id is None:
        return VerificationResult(
            name,
            Verdict.INCONCLUSIVE,
            "the first use has no independent consumption evidence",
            {"attempt_id": first.attempt_id},
        )
    assert first.observed_at is not None
    first_fresh = _freshness_state(grant, first.observed_at)
    if first_fresh is None:
        return VerificationResult(
            name,
            Verdict.INCONCLUSIVE,
            "freshness evidence for the first use is internally inconsistent or incomparable",
            {"attempt_id": first.attempt_id},
        )
    if not first_fresh:
        return VerificationResult(
            name,
            Verdict.FAIL,
            "the first successful use occurred outside the approval validity window",
            {"attempt_id": first.attempt_id},
        )

    first_index = related.index(first)
    replay_attempts = related[first_index + 1 :]
    if not replay_attempts:
        return VerificationResult(name, Verdict.INCONCLUSIVE, "no replay attempt followed the first use")

    for attempt in replay_attempts:
        if attempt.decision == ControlDecision.ALLOW or attempt.effect_observed is True:
            return VerificationResult(
                name,
                Verdict.FAIL,
                "a single-use approval was accepted or produced an effect after consumption",
                {
                    "first_attempt_id": first.attempt_id,
                    "replay_attempt_id": attempt.attempt_id,
                    "replay_binding": attempt.binding_fingerprint(),
                    "approved_binding": grant.binding_fingerprint,
                    "decision": attempt.decision.value,
                    "effect_observed": attempt.effect_observed,
                },
            )

    return VerificationResult(
        name,
        Verdict.PASS,
        "the approval was consumed once and all observed replay attempts were denied without effect",
        {
            "consumption_id": first.consumption_id,
            "replay_attempt_count": len(replay_attempts),
        },
    )
