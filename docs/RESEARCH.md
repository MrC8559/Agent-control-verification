# Research checkpoint

Checked: 2026-09-16

## Thesis

There is substantial activity in generic agent red teaming and runtime security. ACV should not compete by becoming another list of prompt attacks.

The more differentiated research question is:

> Can a developer independently verify that an agent control plane's decision is enforced at the actual point of effect?

## Adjacent work

### OWASP Agent Security Regression Harness

Repository: https://github.com/OWASP/Agent-Security-Regression-Harness

The project already covers executable agent-security scenarios, traces, adapters, and CI-oriented regression testing. That makes a generic "agent security tests in CI" clone a weak thesis.

**Implication for ACV:** specialize in the decision, invocation, and effect boundary and integrate with scenario harnesses rather than duplicating them.

### OWASP Agent Control Standard

Repository: https://github.com/GenAI-Security-Project/agent-control-standard

ACS is emerging work around instrumenting and governing agent actions. Its active conformance discussions make the distinction between a claimed/returned decision and demonstrable enforcement especially relevant.

**Implication for ACV:** treat ACS as an important potential integration and evidence vocabulary, not as a badge. ACV is not currently an ACS conformance program.

### OWASP Top 10 for Agentic Applications

Reference: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

The taxonomy includes risks around goal hijacking, tool misuse, identity/privilege abuse, supply chains, code execution, memory/context, inter-agent communication, cascading failures, trust exploitation, and rogue agents.

**Implication for ACV:** map properties to relevant risks, but keep tests property-based and observable rather than producing an arbitrary aggregate score.

### AgentCanary

Repository: https://github.com/antgroup/Agent3Sigma-Canary

AgentCanary evaluates agents in controlled environments with real tool trajectories.

**Implication for ACV:** controlled environments are proven useful. ACV should focus on control-plane enforcement evidence rather than broad agent capability/safety benchmarking.

## Product hypothesis

A useful developer workflow could eventually be:

```text
change agent / model / host / policy
then run the control-verification suite
then capture decision + invocation + effect evidence
then return PASS / FAIL / INCONCLUSIVE
then block regressions in CI
```

A future hosted product could retain private evidence, compare versions, run controlled matrices, and provide audit exports. That is a hypothesis, not current product-market-fit evidence.

## What would falsify the thesis?

We should change direction if evidence shows that:

1. established open-source tooling already verifies the same effect boundary across major hosts with equivalent evidence;
2. agent hosts do not expose enough independent effect evidence for useful black-box verification;
3. developers/security teams do not consider decision/effect mismatch a material problem;
4. integrations require invasive host modifications that defeat independent verification;
5. the project collapses into a duplicate of generic prompt-injection testing.

## Next research questions

- Which real host gives the smallest useful decision/effect integration surface?
- Can we independently observe effects without trusting the same component that reports the decision?
- What evidence is required to distinguish FAIL from INCONCLUSIVE?
- How should approval replay and TOCTOU mutation be represented?
- Which ACS requirements are observable black-box versus self-attested?
- Can evidence bundles remain useful while redacting user data and secrets?
