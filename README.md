# Agent Control Verification

> **Verify that AI-agent security decisions are enforced at the point of effect.**

Agent Control Verification (ACV) is an early-stage open-source research project for testing a simple but important proposition:

> A security control saying **DENY** is not evidence that the prohibited effect did not happen.

ACV is being built to observe both sides of an agent control boundary:

1. **What the control decided** — allow, deny, ask, defer, or error.
2. **What the environment actually did** — file mutation, message send, network request, secret access, or another consequential effect.

The project is intentionally focused on **decision-to-effect verification**, not on building another generic prompt-injection scanner.

## Status

**Experimental / pre-alpha. Do not treat ACV output as a certification or security guarantee.**

The current checkpoint is a deterministic synthetic laboratory. It proves the core evidence model and catches deliberately vulnerable demo targets. No production agent, model provider, or third-party system is contacted.

## Why this exists

Agent security tooling is rapidly expanding, including red-team harnesses, runtime gateways, policy engines, and emerging control standards. Those are valuable, but they create a second-order question:

**How do we verify that the control itself actually controlled the effect?**

Examples:

- a hook reports `DENY`, but a tool still runs;
- an approved action is mutated after approval but before execution;
- an approval is replayed for a second invocation;
- a control becomes unavailable and the host silently proceeds;
- the action happens, but the audit trail does not record it;
- a decision applies to one identity or tool but is reused by another.

ACV aims to make those properties reproducible and testable.

## First principles

- **Observe effects, not claims.**
- **PASS requires evidence.**
- **Unknown evidence becomes INCONCLUSIVE, not PASS.**
- **Security decisions should be bound to the exact action they authorize.**
- **Tests should be deterministic before they become model-dependent.**
- **Synthetic environments first; no accidental real-world side effects.**
- **Standards mappings are references, not claims of certification.**

## Quick start

Requires Python 3.11+.

```bash
python -m pip install -e .
python -m agent_control_verification demo
python -m unittest discover -s tests -v
```

The demo intentionally includes both secure and insecure implementations. Example output contains results such as:

```text
PASS  deny_prevents_effect   hardened-deny
FAIL  deny_prevents_effect   deny-but-executes
FAIL  allow_binds_exact_action   mutate-after-allow
FAIL  consequential_effect_is_audited   missing-audit
```

A failing demo target is a **successful test of the verifier**, not a project failure.

## What is implemented

The initial laboratory contains:

- a stable `Action` fingerprint that binds tool, target, and arguments;
- explicit control decision records;
- synthetic file, email, and HTTP side effects;
- audit-event evidence;
- observation of effects after a target runs;
- three security properties:
  - `deny_prevents_effect`
  - `allow_binds_exact_action`
  - `consequential_effect_is_audited`
- hardened and intentionally vulnerable demo targets;
- deterministic unit tests;
- GitHub Actions CI.

## Intended direction

The next phases are to add:

1. approval binding and replay tests;
2. fail-open / control-unavailable scenarios;
3. identity and tool-scope checks;
4. evidence bundles with reproducible environment metadata;
5. adapters for real agent hosts and control planes;
6. mappings to the OWASP Agentic Top 10 and Agent Control Standard;
7. cross-version regression matrices for hosts, frameworks, and control layers.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), [`docs/RESEARCH.md`](docs/RESEARCH.md), and [`ROADMAP.md`](ROADMAP.md).

## Relationship to existing work

ACV is deliberately adjacent to — not a replacement for — projects such as:

- [OWASP Agent Security Regression Harness](https://github.com/OWASP/Agent-Security-Regression-Harness)
- [OWASP Agent Control Standard](https://github.com/GenAI-Security-Project/agent-control-standard)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [AgentCanary](https://github.com/antgroup/Agent3Sigma-Canary)

Those projects helped narrow ACV's thesis toward verification of the **decision/execution/effect boundary**.

This repository is independent and is not an OWASP project or an assertion of OWASP conformance.

## Safety boundary

The repository must remain safe to clone and run.

Tests must default to local synthetic resources. Do not add code that attacks third-party systems, exfiltrates real secrets, scans public targets without authorization, or makes live consequential calls by default.

## License

Apache-2.0.
