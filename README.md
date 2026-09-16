# Agent Control Verification

> Verify that AI-agent security decisions are enforced at the point of effect.

Agent Control Verification (ACV) is an early-stage open-source research project for testing a simple security property:

> A control reporting `DENY` does not, by itself, prove that the prohibited effect was prevented.

ACV records two separate evidence sources:

1. What the control decided: allow, deny, ask, defer, or error.
2. What the environment actually did: file mutation, message send, network request, secret access, or another consequential effect.

The project focuses on decision-to-effect verification. It is not intended to be a generic prompt-injection scanner.

## Status

Experimental and pre-alpha. ACV output is not a certification or security guarantee.

The current implementation includes a deterministic synthetic laboratory, an out-of-process filesystem effect observer, a deterministic approval model, and a control-failure posture model. No production agent, model provider, human-approval system, or third-party service is contacted by the default test suite.

## Why this exists

Agent systems can fail between a control decision and the resulting tool effect. Examples include:

- a hook reports `DENY`, but a tool still runs;
- an approved action is changed before execution;
- an approval is replayed for a later invocation;
- a control becomes unavailable and the host proceeds;
- an action occurs without matching audit evidence;
- authority for one identity, session, or tool is reused by another.

ACV turns these cases into explicit, reproducible properties.

## Principles

- Observe effects independently where the environment allows it.
- Require evidence for `PASS`.
- Return `INCONCLUSIVE` when evidence is missing or contradictory.
- Bind authorization to the exact action and authority scope.
- Prefer deterministic tests before model-dependent tests.
- Use synthetic local effects by default.
- Treat standards as references unless external conformance has actually been established.

## Quick start

Requires Python 3.11+.

```bash
python -m pip install -e .
python -m agent_control_verification demo
python -m unittest discover -s tests -v
```

The demo contains secure and deliberately vulnerable implementations. Typical results include:

```text
PASS  deny_prevents_effect   hardened-deny
FAIL  deny_prevents_effect   deny-but-executes
FAIL  allow_binds_exact_action   mutate-after-allow
FAIL  consequential_effect_is_audited   missing-audit
```

A failing vulnerable fixture is expected. Its purpose is to prove that the verifier can detect the violation.

The process-boundary tests include a target that returns `DENY` after writing a file. ACV derives the verdict from the parent process's before/after filesystem evidence rather than the target's own effect report.

Approval tests cover exact semantic binding, cross-identity/session/tool misuse, post-approval argument mutation, expiry, single-use replay, and explicit `INCONCLUSIVE` outcomes when freshness or consumption evidence is missing.

Control-failure tests distinguish policy denial, explicit security refusal, timeout, transport loss, and malformed responses. A configured fail-open posture is recorded as evidence. It does not turn ungoverned execution into `PASS`.

## Implemented properties

The current laboratory includes:

- stable action fingerprints;
- explicit control decision records;
- synthetic file, email, and HTTP effects;
- audit-event evidence;
- out-of-process filesystem observation using SHA-256 snapshots;
- a minimal JSON subprocess decision contract;
- approval binding over principal, session, tool, target, and arguments;
- approval freshness checks;
- single-use approval replay verification;
- explicit control-failure cause and posture evidence;
- `PASS`, `FAIL`, and `INCONCLUSIVE` results;
- deterministic regression tests and GitHub Actions CI.

Relevant design notes:

- [`docs/PROCESS_BOUNDARY.md`](docs/PROCESS_BOUNDARY.md)
- [`docs/APPROVAL_MODEL.md`](docs/APPROVAL_MODEL.md)
- [`docs/FAILURE_POSTURE.md`](docs/FAILURE_POSTURE.md)
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- [`docs/RESEARCH.md`](docs/RESEARCH.md)

## Next work

The next planned steps are:

1. define a stable JSON evidence/report schema;
2. strengthen identity and tool-scope evidence;
3. create reproducible evidence bundles;
4. select the first real agent host/control integration;
5. map implemented properties to relevant OWASP agent-security work;
6. add version-pinned regression matrices for real hosts and control layers.

See [`ROADMAP.md`](ROADMAP.md) for the current sequence.

## Related work

ACV is adjacent to projects such as:

- [OWASP Agent Security Regression Harness](https://github.com/OWASP/Agent-Security-Regression-Harness)
- [OWASP Agent Control Standard](https://github.com/GenAI-Security-Project/agent-control-standard)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [AgentCanary](https://github.com/antgroup/Agent3Sigma-Canary)

ACV is independent. It is not an OWASP project and does not currently claim OWASP or ACS conformance.

## Safety boundary

The repository must remain safe to clone and run.

Default tests use local synthetic resources. Do not add code that attacks third-party systems, exfiltrates real secrets, scans public targets without authorization, or performs live consequential actions by default.

## License

Apache-2.0.
