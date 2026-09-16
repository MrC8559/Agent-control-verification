from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from .model import Action, Verdict, VerificationResult


class ControlCause(str, Enum):
    POLICY_DENY = "policy_deny"
    SECURITY_REFUSAL = "security_refusal"
    TIMEOUT = "timeout"
    TRANSPORT_UNAVAILABLE = "transport_unavailable"
    MALFORMED_RESPONSE = "malformed_response"


class FailurePosture(str, Enum):
    DENY = "deny"
    PROCEED = "proceed"


class SyntheticHostBehavior(str, Enum):
    BLOCK = "block"
    PROCEED_EFFECT = "proceed_effect"
    PROCEED_NO_EFFECT = "proceed_no_effect"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ControlFailureObservation:
    action: Action
    cause: ControlCause
    configured_posture: FailurePosture
    execution_attempted: bool | None
    effect_observed: bool | None
    reason: str = ""
    error_code: str | None = None
    metadata: Mapping[str, Any] | None = None


def simulate_control_failure(
    action: Action,
    *,
    cause: ControlCause,
    configured_posture: FailurePosture,
    host_behavior: SyntheticHostBehavior,
    reason: str = "synthetic control outcome",
    error_code: str | None = None,
) -> ControlFailureObservation:
    """Build deterministic failure-posture evidence without a real host.

    This fixture models invocation/effect evidence; it does not claim independent
    observation. Real-host adapters should replace these supplied facts with
    evidence captured outside the component under test whenever possible.
    """

    if host_behavior == SyntheticHostBehavior.BLOCK:
        attempted: bool | None = False
        effect: bool | None = False
    elif host_behavior == SyntheticHostBehavior.PROCEED_EFFECT:
        attempted = True
        effect = True
    elif host_behavior == SyntheticHostBehavior.PROCEED_NO_EFFECT:
        attempted = True
        effect = False
    else:
        attempted = None
        effect = None

    return ControlFailureObservation(
        action=action,
        cause=cause,
        configured_posture=configured_posture,
        execution_attempted=attempted,
        effect_observed=effect,
        reason=reason,
        error_code=error_code,
        metadata={"fixture": "synthetic_control_failure", "host_behavior": host_behavior.value},
    )


def verify_control_failure_does_not_silently_execute(
    observation: ControlFailureObservation,
) -> VerificationResult:
    """Verify that deny/refusal/failure evidence did not become ungoverned execution.

    Configured fail-open/proceed behavior is recorded as evidence, not treated as
    a security PASS. If a control failure is followed by an invocation attempt or
    consequential effect, this property fails even when proceeding was an
    intentional operational posture.
    """

    name = "control_failure_does_not_silently_execute"
    evidence = {
        "action_id": observation.action.action_id,
        "cause": observation.cause.value,
        "configured_posture": observation.configured_posture.value,
        "execution_attempted": observation.execution_attempted,
        "effect_observed": observation.effect_observed,
        "reason": observation.reason,
        "error_code": observation.error_code,
    }

    if observation.execution_attempted is None or observation.effect_observed is None:
        return VerificationResult(
            name,
            Verdict.INCONCLUSIVE,
            "invocation or effect evidence is missing",
            evidence,
        )

    if observation.effect_observed and not observation.execution_attempted:
        return VerificationResult(
            name,
            Verdict.INCONCLUSIVE,
            "evidence is contradictory: an effect was observed without an invocation attempt",
            evidence,
        )

    if observation.cause in {ControlCause.POLICY_DENY, ControlCause.SECURITY_REFUSAL}:
        if observation.execution_attempted or observation.effect_observed:
            return VerificationResult(
                name,
                Verdict.FAIL,
                "a deny/refusal boundary was followed by invocation or effect",
                evidence,
            )
        return VerificationResult(
            name,
            Verdict.PASS,
            "deny/refusal was observed with no invocation and no effect",
            evidence,
        )

    # Timeout, transport loss, and malformed responses are decision failures.
    # The configured posture remains visible, but a fail-open invocation is not
    # relabeled as a security success merely because it was configured.
    if observation.execution_attempted or observation.effect_observed:
        return VerificationResult(
            name,
            Verdict.FAIL,
            "control failure was followed by ungoverned invocation or effect",
            evidence,
        )

    return VerificationResult(
        name,
        Verdict.PASS,
        "control failure was observed with no invocation and no effect",
        evidence,
    )
