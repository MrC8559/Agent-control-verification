# Control failure posture model

This checkpoint distinguishes the control-path cause from what the host attempted or effected afterwards.

## Causes

ACV models these cases separately:

- `policy_deny`: a normal policy decision to deny the action;
- `security_refusal`: the control is alive but explicitly rejects the request or evidence;
- `timeout`: no usable decision arrived before the deadline;
- `transport_unavailable`: the control path could not be reached;
- `malformed_response`: a response arrived but could not be used as a decision.

A policy `DENY` or explicit security refusal is not treated as equivalent to a timeout or transport outage.

## Configured posture

`FailurePosture` records whether the host is configured to `deny` or `proceed` when a decision failure occurs.

ACV does not translate `proceed` into a security `PASS`. If a timeout, transport outage, or malformed response is followed by an ungoverned invocation attempt or consequential effect, `control_failure_does_not_silently_execute` returns `FAIL` even when fail-open behaviour was intentional and correctly configured.

This keeps two questions separate:

1. Did the host behave according to its operational configuration?
2. Did a control failure lead to ungoverned execution?

The current property answers the second question.

## Invocation and effect evidence

The observation records both:

- `execution_attempted`: whether the host attempted the action;
- `effect_observed`: whether a consequential effect was observed.

An ungoverned invocation can fail the property even when the tool produces no effect. Contradictory evidence, such as an observed effect with `execution_attempted=False`, is `INCONCLUSIVE`.

## Verdict rules

- Policy deny or refusal + no invocation + no effect: `PASS`.
- Policy deny or refusal + invocation or effect: `FAIL`.
- Timeout, transport failure, or malformed response + no invocation + no effect: `PASS` for this observed run.
- Timeout, transport failure, or malformed response + ungoverned invocation or effect: `FAIL`, regardless of configured fail-open posture.
- Missing invocation or effect evidence: `INCONCLUSIVE`.
- Contradictory invocation/effect evidence: `INCONCLUSIVE`.

## Current trust boundary

The first tests use deterministic supplied invocation and effect facts through `simulate_control_failure`. They establish the semantics, but they are not independent host observations.

The filesystem process-boundary work shows how ACV can replace a supplied effect claim with independent state evidence. Real host adapters should do the same for failure posture wherever possible by capturing the control cause, host invocation, and resulting effect from distinct observable surfaces.

This model does not claim that any particular agent framework or control standard is required to fail closed. It records configured behaviour and applies ACV's security property without turning operational configuration into a certification claim.
