# Approval binding and replay model

This checkpoint defines approval semantics before ACV integrates with a real agent host or human-approval system.

## Security properties

ACV currently tests three approval properties:

1. **Exact binding**: an approval is bound to the principal, session, tool, target, and arguments that were approved.
2. **Freshness**: an approval can only be exercised inside its observed validity window.
3. **Single use**: once a single-use approval is consumed, later attempts using the same approval must not be allowed or produce an effect.

Each property returns `PASS`, `FAIL`, or `INCONCLUSIVE`. Missing effect, timestamp, or consumption evidence is never converted into `PASS`.

Exact-binding and freshness verification require the attempt to reference the supplied grant's approval identifier. A different identifier returns `INCONCLUSIVE`, even when the semantic binding and timestamps match, because that grant cannot establish the referenced approval's validity.

## Semantic binding fingerprint

The approval binding fingerprint is SHA-256 over canonical JSON containing:

```text
principal_id
session_id
tool
target
arguments
```

`action_id` is intentionally excluded. It identifies an execution attempt, while the approval describes the semantic action that was approved. Replay is evaluated separately using the approval identifier, observed attempts, and consumption evidence.

Changing any bound field creates a different binding. An approval for one agent, session, tool, recipient, path, or argument set cannot silently authorize another.

## Evidence model

`ApprovalGrant` records:

- approval identifier;
- semantic binding fingerprint;
- issued time;
- expiry time;
- whether the approval is single-use.

`ApprovalAttempt` records:

- attempt identifier;
- approval identifier presented;
- action;
- principal and session;
- control decision;
- whether an effect was observed;
- observed time;
- optional consumption evidence identifier.

The current deterministic model treats `consumption_id` as an evidence reference rather than cryptographic proof. A real integration must define where consumption evidence comes from and whether ACV can observe it independently.

## Verdict examples

- Exact approved action + `ALLOW` + observed effect: **PASS** for exact binding.
- Mutated action + `ALLOW` or observed effect: **FAIL**.
- Mutated action + `DENY` + no observed effect: **PASS** for binding enforcement.
- Expired approval + observed effect: **FAIL**.
- Expired approval + `DENY` + no effect: **PASS** for freshness enforcement.
- First single-use execution consumed, later replay denied with no effect: **PASS**.
- Later replay accepted or producing an effect: **FAIL**.
- Missing effect, timestamp, validity, or first-use consumption evidence: **INCONCLUSIVE**.

## Current trust boundary

These approval tests are deterministic model-level tests. Unlike the out-of-process filesystem checkpoint, `effect_observed` and `consumption_id` are currently supplied evidence fields rather than independently measured host facts.

This checkpoint establishes the verification semantics first. A real-host integration should replace supplied facts with independently captured decision, effect, and consumption evidence wherever the host permits it.

ACV does not currently claim to verify a real human-approval product, identity provider, agent framework, or OWASP Agent Control Standard deployment.
