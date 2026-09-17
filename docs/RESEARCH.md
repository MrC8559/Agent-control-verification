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

## 2026-09-17 control-boundary sweep

This sweep looked for failure modes that remain close to ACV's thesis and can plausibly be measured with independent evidence. It deliberately did not turn every upstream bug report into an ACV feature.

### Existing ACV choices were reinforced

The OWASP Agent Control Standard v0.1.0 now has a public reference implementation. Its own README documents a default `proceed` failure posture when the Guardian crashes, hangs, or is unreachable unless fail-closed behavior is configured. That is strong evidence that ACV's separation of control failure, invocation evidence, and observed effect addresses a real design boundary.

Source: https://github.com/GenAI-Security-Project/agent-control-standard

This does not establish ACS conformance for ACV and does not establish a vulnerability in ACS. It reinforces the value of measuring failure posture explicitly instead of treating control availability as proof of enforcement.

### Five post-v0.1.0 properties are worth preserving

1. **Control-authorized modification binding.** ACS exposes `modify` as a first-class decision, and real host hooks can rewrite tool input. ACV needs to distinguish an explicitly authorized rewrite from an unauthorized mutation after approval. Tracked in #20.
2. **Deny persistence across retry and escalation.** A host can record a deny correctly and still later route the same action through retry, sandbox escalation, or approval logic. One Codex report on version `0.144.6` demonstrates why the state transition itself needs verification. Tracked in #21.
3. **Delegation scope and attribution.** Reports across Claude Code, OpenCode, and Codex show that subagent control coverage and parent-child correlation are difficult to assume safely. Recent authorization research independently identifies scope propagation and principal chains as central gaps. Tracked in #22.
4. **Control-plane integrity.** A hook or policy is not a reliable control boundary if the governed agent can silently weaken the active configuration that produces later decisions. ACV should distinguish control provenance from control integrity. Tracked in #23.
5. **MCP credential boundary effects.** The MCP `2026-07-28` authorization guidance explicitly requires resource-bound tokens and forbids inbound-token passthrough to upstream APIs. Both properties can be tested safely with synthetic localhost services and independently observed downstream requests. Tracked in #24.

### Sources that shaped those issues

- ACS v0.1.0: https://github.com/GenAI-Security-Project/agent-control-standard
- Claude Code hooks guide: https://code.claude.com/docs/en/hooks-guide
- Codex retry/escalation report: https://github.com/openai/codex/issues/39872
- Codex spawn correlation proposal: https://github.com/openai/codex/issues/44095
- Claude Code subagent enforcement reports: https://github.com/anthropics/claude-code/issues/21460 and https://github.com/anthropics/claude-code/issues/67424
- OpenCode subagent hook report: https://github.com/anomalyco/opencode/issues/5894
- Claude Code control self-modification report: https://github.com/anthropics/claude-code/issues/32376
- MCP authorization security considerations: https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/authorization/security-considerations.mdx
- MCP security best practices: https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/docs/2026-07-28/tutorials/security/security_best_practices.mdx
- Authorization architectures review, 2026-09-14: https://arxiv.org/abs/2609.15906
- Delegation-security research: https://arxiv.org/abs/2608.15888

Upstream issue reports are evidence that a property is worth measuring. They are not treated as proof that another version, platform, or host has the same behavior.

### Lower-priority signal to monitor

Codex issue #32573 reports that a host can block an action while still rendering raw tool input after a sanitized denial reason. This suggests a possible future end-to-end redaction property, but it is currently secondary to ACV's authorization and effect boundary.

Source: https://github.com/openai/codex/issues/32573

Do not expand the immediate roadmap for it unless evidence privacy becomes a concrete blocker for publishing or consuming ACV artifacts.

### Suggested order after v0.1.0

The issues are research candidates, not commitments. If the first real-host milestone succeeds, the smallest useful sequence currently looks like:

1. #20, because explicit modification semantics extend ACV's existing exact-action model without requiring another host;
2. #21, because retry and escalation can be measured on the same host family as the first integration;
3. #23, because control integrity determines whether later host-level conclusions are meaningful;
4. #22, once a host exposes enough subagent correlation to avoid heuristic attribution;
5. #24, as a separate synthetic MCP authorization boundary experiment.

The sequence should change if live evidence shows a more important gap.
