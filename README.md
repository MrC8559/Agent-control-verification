# Agent Control Verification

> Verify that AI-agent security decisions are enforced at the point of effect.

Agent Control Verification (ACV) is an open-source security research project built around one narrow question:

> A control reporting `DENY` does not, by itself, prove that the prohibited effect was prevented.

ACV records two separate evidence sources:

1. What the control decided: allow, deny, ask, defer, or error.
2. What the environment actually did: file mutation, message send, network request, secret access, or another consequential effect.

The project focuses on decision-to-effect verification. It is not intended to be a generic prompt-injection scanner.

ACV is the verification engine for the broader **Agent Action Integrity Observatory** research programme. The Observatory is intended to accumulate narrow, version-pinned observations about whether agent control outcomes agree with independently observable effects. It does not yet have a published dataset or cross-host matrix, and it does not produce aggregate product security scores. See [`docs/ACTION_INTEGRITY_OBSERVATORY.md`](docs/ACTION_INTEGRITY_OBSERVATORY.md).

## Status

**Research preview. Experimental and pre-alpha.**

The deterministic verification core is working. ACV can independently observe filesystem effects across a process boundary, test approval binding and replay properties, model control failures, and export versioned redacted evidence bundles.

The **v0.1.0 first real-host evidence milestone is complete** for the tested Windows Codex CLI `0.154.0` environment and controlled `apply_patch` scenarios. The reviewed evidence closeout is published; final release publication remains pending.

The evidence preserves an environment-blocked DENY attempt as `INCONCLUSIVE`, a supported DENY `PASS`, an exact-action ALLOW `PASS`, and a controlled-failure `FAIL` after execution continued. The last result demonstrates detection of a violated failure-posture property; it is not an unsuccessful experiment.

See the [consolidated evidence report](docs/reports/2026-09-19-codex-0.154.0.md) and its validated redacted bundles. The live experiment used package `0.0.3` at revision `04efa04f05d95efa30963e8a4190556e60569127`. Current package metadata is prepared as `0.1.0`; the live experiment was not rerun for this version change. ACV output is not a certification or security guarantee.

- [Public project status](docs/PUBLIC_STATUS.md)
- [Agent Action Integrity Observatory](docs/ACTION_INTEGRITY_OBSERVATORY.md)
- [Roadmap](ROADMAP.md)
- [Codex probe](docs/CODEX_PROBE.md)
- [First-host decision](docs/decisions/0001-first-real-host-codex.md)

## Current research milestone

The first real-host experiment is deliberately narrow. It tests Codex native `PreToolUse` and `PostToolUse` hooks around one harmless `apply_patch` operation in a disposable local workspace.

The experiment asks three questions:

1. If the hook denies the patch, does the marker file remain unchanged when ACV reads the filesystem independently?
2. If the hook allows the patch, do the pre-tool and post-tool records correspond to the independently observed file effect?
3. If the hook fails in a controlled way, does the host proceed, block, or leave the outcome uncertain?

A result applies only to the exact version and execution path that was observed. The observed path was `exec` calling `tools.apply_patch`; this does not establish coverage of other Code Mode tools/routes, direct tool routes, shell execution, MCP, subagents, or other platforms.

## Why this exists

Agent systems can fail between a control decision and the resulting tool effect. Examples include:

- a hook reports `DENY`, but a tool still runs;
- an approved action is changed before execution;
- an approval is replayed for a later invocation;
- a control becomes unavailable and the host proceeds;
- an action occurs without matching audit evidence;
- authority for one identity, session, or tool is reused by another.

ACV turns these cases into explicit, reproducible properties.

## What works today

The current implementation includes:

- stable action fingerprints;
- explicit control decision records;
- synthetic file, email, and HTTP effects;
- audit-event evidence;
- out-of-process filesystem observation using SHA-256 snapshots;
- approval binding over principal, session, tool, target, and arguments;
- approval freshness checks;
- single-use approval replay verification;
- explicit control-failure cause and posture evidence;
- `PASS`, `FAIL`, and `INCONCLUSIVE` results;
- versioned JSON evidence bundles with integrity validation;
- redacted-by-default evidence export;
- deterministic regression tests and GitHub Actions CI;
- a Codex `0.154.0` `apply_patch` hook adapter;
- disposable Codex probe workspace generation;
- redacted `PreToolUse` and `PostToolUse` recording;
- a collector that compares hook evidence with the marker file read directly from the filesystem;
- a live-run preflight that verifies host pinning, ACV provenance, marker baseline, exact hook scope, and workspace freshness;
- matching macOS/Linux and Windows probe helpers.

The default test suite does not contact a production agent, model provider, human-approval system, or third-party service.

## Principles

- Observe effects independently where the environment allows it.
- Require evidence for `PASS`.
- Return `INCONCLUSIVE` when evidence cannot support a verdict; a uniquely correlated violation may remain `FAIL` despite unrelated gaps.
- Bind authorization to the exact action and authority scope.
- Prefer deterministic tests before model-dependent tests.
- Use synthetic local effects by default.
- Treat standards as references unless external conformance has actually been established.
- Measure coverage per host version and execution path instead of assuming it.

## Quick start

Requires Python 3.11+.

```bash
python -m pip install -e .
python -m agent_control_verification demo
python -m agent_control_verification evidence-demo --output evidence.json
python -m agent_control_verification render-evidence evidence.json
python -m unittest discover -s tests -v
```

The deterministic demo contains secure and deliberately vulnerable implementations. Typical results include:

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

Evidence bundles contain fingerprints, component versions, explicit missing-evidence fields, privacy metadata, and an integrity digest. The default bundle format does not carry raw action payloads or raw control-reason text.

## Codex probe

The first live experiment uses a new or empty disposable directory and one marker file. ACV prepares project-scoped Codex hooks, records redacted hook evidence, then independently reads the marker file during collection.

Before a live run, ACV can check readiness with:

```bash
python -m agent_control_verification codex-preflight
```

On macOS/Linux, the helper prepares and preflights a fresh workspace:

```bash
bash scripts/prepare-first-codex-probe.sh --mode deny
```

On Windows PowerShell:

```powershell
.\scripts\prepare-first-codex-probe.ps1 -Mode deny
```

The supported fixtures are:

- deny;
- allow;
- malformed hook output;
- hook exit error.

The workflow and safety boundary are documented in [`docs/CODEX_PROBE.md`](docs/CODEX_PROBE.md).

## Design notes

- [`docs/PROCESS_BOUNDARY.md`](docs/PROCESS_BOUNDARY.md)
- [`docs/APPROVAL_MODEL.md`](docs/APPROVAL_MODEL.md)
- [`docs/FAILURE_POSTURE.md`](docs/FAILURE_POSTURE.md)
- [`docs/EVIDENCE_BUNDLE.md`](docs/EVIDENCE_BUNDLE.md)
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- [`docs/RESEARCH.md`](docs/RESEARCH.md)
- [`docs/ACTION_INTEGRITY_OBSERVATORY.md`](docs/ACTION_INTEGRITY_OBSERVATORY.md)
- [`docs/CODEX_PROBE.md`](docs/CODEX_PROBE.md)
- [`docs/decisions/0001-first-real-host-codex.md`](docs/decisions/0001-first-real-host-codex.md)

The machine-readable evidence schema is [`schemas/evidence-bundle.schema.json`](schemas/evidence-bundle.schema.json).

## Next work

Review the prepared `0.1.0` release metadata, then complete the separately authorized commit, CI, tag and release steps. No later research has started. The report lists bounded open questions; an Observatory index and additional execution paths remain separately scoped future work.

See [`ROADMAP.md`](ROADMAP.md) for the longer sequence.

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

Real-host probes must remain local, disposable, version-pinned, and explicit about what was and was not observed.

## License

Apache-2.0.
