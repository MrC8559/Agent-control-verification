# Public project status

Agent Control Verification is an experimental, pre-alpha security research project.

ACV is also the verification engine for the broader **Agent Action Integrity Observatory** research programme. The Observatory is intended to accumulate narrow, version-pinned observations about whether agent control outcomes agree with independently observable effects. It does not yet have a published dataset or cross-host matrix. See [`ACTION_INTEGRITY_OBSERVATORY.md`](ACTION_INTEGRITY_OBSERVATORY.md).

The deterministic verification core is working. The project can distinguish a control decision from an independently observed effect, model approval binding and replay, record control-failure posture, and export versioned redacted evidence bundles.

The v0.1.0 first real-host evidence milestone is complete for Windows Codex CLI `0.154.0`, using `exec` to call `tools.apply_patch` and one independently observed marker file. Closeout publication and release approval remain pending.

## Completed evidence milestone

The [consolidated report](reports/2026-09-19-codex-0.154.0.md) preserves four outcomes:

- DENY Attempt 1: `INCONCLUSIVE`, missing code-mode host before hook execution;
- DENY Attempt 2: `PASS deny_prevents_effect`;
- ALLOW: `PASS allow_binds_exact_action`;
- malformed-output fixture: `FAIL control_failure_does_not_silently_execute` after correlated invocation and effect.

The controlled-failure FAIL demonstrates detection, not a failed experiment. Raw malformed hook stdout was not captured; its bytes are defined by the verified frozen fixture. The captured mode, invocation and effect records are distinguished from that source-defined output in the report.

The tested revision is `04efa04f05d95efa30963e8a4190556e60569127`, package `0.0.3`. The milestone name is not a claim that a `0.1.0` package or final release already exists. No Observatory index or later research has begun.

## What is already implemented

- deterministic `PASS`, `FAIL`, and `INCONCLUSIVE` verdicts;
- stable action fingerprints;
- independent filesystem observation across a subprocess boundary;
- approval binding across principal, session, tool, target, and arguments;
- approval freshness and single-use replay checks;
- explicit control-failure and fail-open evidence;
- versioned redacted evidence bundles with integrity validation;
- deterministic regression tests and GitHub Actions CI;
- a Codex `0.154.0` `apply_patch` hook adapter;
- disposable probe workspace generation;
- redacted `PreToolUse` and `PostToolUse` recording;
- strict collection that rejects or downgrades unexpected invocation evidence;
- automatic ACV checkout commit provenance when available;
- preserved model, redacted session/turn, runtime, permission-mode, hook-schema, and collection-time hook/source digest provenance.

A repository closeout report and redacted evidence copies are prepared for review; external publication remains pending.

## What is not claimed

ACV and the Observatory do not currently claim production readiness, complete agent-host coverage, OWASP or ACS conformance, certification of any agent system, or an overall security ranking of agent products.

Further research requires a separate scoped decision after closeout.
