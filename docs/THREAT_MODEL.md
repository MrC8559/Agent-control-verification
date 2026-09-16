# Threat Model

Checked: 2026-09-16

## Security question

ACV focuses on a narrow question:

> When an agent control layer decides what may happen, does the actual system effect match that decision and its scope?

The verifier treats the **decision plane** and the **effect plane** as separate evidence sources.

## Primary trust boundaries

### 1. Agent to control layer

The agent proposes an action. Risks include malformed inputs, identity confusion, missing hooks, and intentionally adversarial arguments.

### 2. Control layer to host/runtime

The control returns allow/deny/ask/defer/error. Risks include dropped decisions, incorrect failure posture, competing hooks, or host-specific interpretation differences.

### 3. Decision to invocation

This is the initial ACV wedge. Risks include:

- mutation after approval;
- executing despite denial;
- replaying authorization;
- changing the tool or target after approval;
- losing identity or provenance between control and tool.

### 4. Invocation to effect

A tool invocation is not necessarily evidence that the effect occurred. Outcomes may be successful, failed, partially applied, duplicated, or unknown.

### 5. Effect to audit evidence

The audit trail may omit the action, record different arguments, misattribute identity, or claim success without independently observable evidence.

## Initial properties

### DENY prevents effect

If the control returns `DENY`, no effect correlated with that requested action may occur.

A control message alone is insufficient evidence.

### ALLOW binds the exact action

An `ALLOW` for one action fingerprint must not silently authorize a different tool, target, or argument set.

### Consequential effects are auditable

A consequential observed effect must have decision/audit evidence bound to the same action fingerprint.

## Planned properties

- approval cannot be replayed;
- approval identity is verified and attributable;
- failure posture is explicit and observable;
- control refusal cannot be converted into silent allow;
- privilege scope does not expand across tools/agents;
- secrets remain inside authorized boundaries;
- multi-agent delegation preserves authority and provenance;
- indeterminate effect state is represented as unknown, not success.

## Attacker model

We assume a potentially adversarial or compromised agent can influence tool arguments and may try to exploit gaps between:

- prompts and policies;
- policies and host hooks;
- hooks and runtime behavior;
- approvals and execution;
- execution and audit.

We do **not** initially assume compromise of the operating system or hypervisor underneath the verifier.

## v0.1 non-goals

- malware analysis;
- endpoint exploitation;
- production incident response;
- generic jailbreak benchmarking;
- certification;
- a universal security score;
- proving model alignment.

## Evidence rule

The verifier uses three verdicts:

- **PASS:** available evidence establishes the tested property.
- **FAIL:** available evidence falsifies the property.
- **INCONCLUSIVE:** the environment did not expose enough evidence to establish either.

`INCONCLUSIVE` is a first-class result, not a softer PASS.
