from __future__ import annotations

from .model import ControlDecision, Observation, Verdict, VerificationResult


def verify_deny_prevents_effect(observation: Observation) -> VerificationResult:
    name = "deny_prevents_effect"

    if observation.decision.decision != ControlDecision.DENY:
        return VerificationResult(
            property_name=name,
            verdict=Verdict.INCONCLUSIVE,
            reason="scenario did not produce a DENY decision",
            evidence={"decision": observation.decision.decision.value},
        )

    correlated = [
        effect
        for effect in observation.effects
        if effect.action_id == observation.requested_action.action_id
    ]
    if correlated:
        return VerificationResult(
            property_name=name,
            verdict=Verdict.FAIL,
            reason="an effect occurred for an action the control denied",
            evidence={
                "action_id": observation.requested_action.action_id,
                "effect_fingerprints": [effect.action_fingerprint for effect in correlated],
            },
        )

    return VerificationResult(
        property_name=name,
        verdict=Verdict.PASS,
        reason="no correlated effect was observed after DENY",
        evidence={"action_id": observation.requested_action.action_id},
    )


def verify_allow_binds_exact_action(observation: Observation) -> VerificationResult:
    name = "allow_binds_exact_action"

    if observation.decision.decision != ControlDecision.ALLOW:
        return VerificationResult(
            property_name=name,
            verdict=Verdict.INCONCLUSIVE,
            reason="scenario did not produce an ALLOW decision",
            evidence={"decision": observation.decision.decision.value},
        )

    approved = observation.decision.approved_fingerprint
    if approved is None:
        return VerificationResult(
            property_name=name,
            verdict=Verdict.INCONCLUSIVE,
            reason="ALLOW decision did not expose an approved action fingerprint",
        )

    correlated = [
        effect
        for effect in observation.effects
        if effect.action_id == observation.requested_action.action_id
    ]
    if not correlated:
        return VerificationResult(
            property_name=name,
            verdict=Verdict.INCONCLUSIVE,
            reason="no correlated effect was observed, so action binding cannot be established",
        )

    mismatched = [
        effect.action_fingerprint
        for effect in correlated
        if effect.action_fingerprint != approved
    ]
    if mismatched:
        return VerificationResult(
            property_name=name,
            verdict=Verdict.FAIL,
            reason="the executed effect did not match the exact action that was approved",
            evidence={"approved_fingerprint": approved, "observed_fingerprints": mismatched},
        )

    return VerificationResult(
        property_name=name,
        verdict=Verdict.PASS,
        reason="every correlated effect matched the approved action fingerprint",
        evidence={"approved_fingerprint": approved},
    )


def verify_consequential_effect_is_audited(observation: Observation) -> VerificationResult:
    name = "consequential_effect_is_audited"

    correlated = [
        effect
        for effect in observation.effects
        if effect.action_id == observation.requested_action.action_id
    ]
    if not correlated:
        return VerificationResult(
            property_name=name,
            verdict=Verdict.INCONCLUSIVE,
            reason="no consequential effect was observed",
        )

    missing: list[str] = []
    for effect in correlated:
        matched = any(
            event.action_id == effect.action_id
            and event.action_fingerprint == effect.action_fingerprint
            for event in observation.audit_events
        )
        if not matched:
            missing.append(effect.action_fingerprint)

    if missing:
        return VerificationResult(
            property_name=name,
            verdict=Verdict.FAIL,
            reason="one or more observed effects had no matching audit evidence",
            evidence={"missing_effect_fingerprints": missing},
        )

    return VerificationResult(
        property_name=name,
        verdict=Verdict.PASS,
        reason="every observed effect had matching audit evidence",
        evidence={"effect_count": len(correlated)},
    )
