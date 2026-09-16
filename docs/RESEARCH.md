# Research checkpoint

Checked: 2026-09-16

## Thesis

There is already substantial activity in generic agent red teaming and runtime security. ACV should not become another collection of prompt attacks.

The project question is narrower:

> Can a developer independently verify that an agent control plane's decision is enforced at the actual point of effect?

## Adjacent work

### OWASP Agent Security Regression Harness

Repository: https://github.com/OWASP/Agent-Security-Regression-Harness

The project already covers executable agent-security scenarios, traces, adapters, and CI-oriented regression testing. Building another generic agent-security test harness would duplicate useful existing work.

ACV should focus on the decision, invocation, and effect boundary, and integrate with scenario harnesses where that is useful.

### OWASP Agent Control Standard

Repository: https://github.com/GenAI-Security-Project/agent-control-standard

ACS is active work on instrumenting and governing agent actions. Its conformance discussions make the distinction between a returned decision and demonstrable enforcement relevant to ACV.

ACV should treat ACS as a possible integration and evidence vocabulary. ACV is not currently an ACS conformance program.

### OWASP Top 10 for Agentic Applications

Reference: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

The taxonomy covers risks including goal hijacking, tool misuse, identity and privilege abuse, supply chains, code execution, memory and context, inter-agent communication, cascading failures, trust exploitation, and rogue agents.

ACV can map specific properties to relevant risks. It should not compress those properties into an arbitrary aggregate score.

### AgentCanary

Repository: https://github.com/antgroup/Agent3Sigma-Canary

AgentCanary evaluates agents in controlled environments with real tool trajectories.

Controlled environments are clearly useful. ACV should remain focused on control-plane enforcement evidence rather than broad agent capability or safety benchmarking.

## Product hypothesis

A useful developer workflow could eventually look like this:

```text
change agent, model, host, or policy
run the control-verification suite
capture decision, invocation, and effect evidence
produce PASS, FAIL, or INCONCLUSIVE
block regressions in CI
```

A hosted product could later retain private evidence, compare versions, run controlled matrices, and provide audit exports. This remains a hypothesis. The project does not yet have product-market-fit evidence.

## What would falsify the thesis?

We should change direction if evidence shows that:

1. established open-source tooling already verifies the same effect boundary across major hosts with equivalent evidence;
2. agent hosts do not expose enough independent effect evidence for useful black-box verification;
3. developers and security teams do not consider decision/effect mismatch a material problem;
4. integrations require invasive host changes that defeat independent verification;
5. the project becomes a duplicate of generic prompt-injection testing.

## Next research questions

- Which real host gives the smallest useful decision/effect integration surface?
- Can ACV observe effects without trusting the same component that reports the decision?
- What evidence is required to distinguish `FAIL` from `INCONCLUSIVE`?
- How should approval replay and TOCTOU mutation be represented?
- Which ACS requirements are observable from outside the control component?
- Can evidence bundles remain useful while redacting user data and secrets?
