# Public project status

Agent Control Verification is an experimental, pre-alpha security research project.

ACV is also the verification engine for the broader **Agent Action Integrity Observatory** research programme. The Observatory is intended to accumulate narrow, version-pinned observations about whether agent control outcomes agree with independently observable effects. It does not yet have a published dataset or cross-host matrix. See [`ACTION_INTEGRITY_OBSERVATORY.md`](ACTION_INTEGRITY_OBSERVATORY.md).

The deterministic verification core is working. The project can distinguish a control decision from an independently observed effect, model approval binding and replay, record control-failure posture, and export versioned redacted evidence bundles.

The current milestone is the first real host integration. ACV has implemented a narrow, version-pinned Codex CLI `0.154.0` experiment around native `PreToolUse` and `PostToolUse` hooks for a harmless `apply_patch` operation in a disposable workspace.

A real-host result will be treated as evidence for the exact tested path and version only. It will not be presented as certification, complete host coverage, or proof about untested tool paths.

## Current milestone

`v0.1.0`: first real integration

The adapter and evidence path are implemented. The remaining gate is live evidence from an actual Codex CLI `0.154.0` session.

The immediate work is to:

1. capture a denied `apply_patch` and independently verify that the marker file did not change;
2. capture an allowed `apply_patch`, pair matching pre/post hook evidence, and verify the expected marker-file effect independently;
3. measure one controlled hook-failure case and preserve the observed host posture;
4. validate and publish the resulting version-pinned `acv-evidence-0.1` bundles;
5. document the exact observed runtime and all unsupported or untested Codex paths.

The publication structure for that result is prepared in [`LIVE_EVIDENCE_REPORT_TEMPLATE.md`](LIVE_EVIDENCE_REPORT_TEMPLATE.md).

If this milestone succeeds, that evidence set becomes the first candidate Observatory observation. A formal observation index remains post-`v0.1.0` work and is tracked separately.

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

No live Codex evidence report has been published yet.

## What is not claimed

ACV and the Observatory do not currently claim production readiness, complete agent-host coverage, OWASP or ACS conformance, certification of any agent system, or an overall security ranking of agent products.

The project will broaden only after the first real integration produces reproducible evidence.
