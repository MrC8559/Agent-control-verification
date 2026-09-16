# Public project status

Agent Control Verification is an experimental, pre-alpha security research project.

The deterministic verification core is working. The project can distinguish a control decision from an independently observed effect, model approval binding and replay, record control-failure posture, and export versioned redacted evidence bundles.

The current milestone is the first real host integration. ACV is building a narrow, version-pinned Codex CLI `0.154.0` experiment around native `PreToolUse` and `PostToolUse` hooks for a harmless `apply_patch` operation in a disposable workspace.

A real-host result will be treated as evidence for the exact tested path and version only. It will not be presented as certification, complete host coverage, or proof about untested tool paths.

## Current milestone

`v0.1.0`: first real integration

The immediate work is to:

1. build the narrow Codex hook adapter;
2. capture a denied `apply_patch` and independently verify that the file did not change;
3. capture an allowed `apply_patch` and pair host hook evidence with the observed file effect;
4. measure one controlled hook-failure case;
5. save the result as a version-pinned `acv-evidence-0.1` bundle;
6. document which Codex paths remain untested.

## What is already implemented

- deterministic `PASS`, `FAIL`, and `INCONCLUSIVE` verdicts;
- stable action fingerprints;
- independent filesystem observation across a subprocess boundary;
- approval binding across principal, session, tool, target, and arguments;
- approval freshness and single-use replay checks;
- explicit control-failure and fail-open evidence;
- versioned redacted evidence bundles with integrity validation;
- deterministic regression tests and GitHub Actions CI.

## What is not claimed

ACV does not currently claim production readiness, complete agent-host coverage, OWASP or ACS conformance, or certification of any agent system.

The project will broaden only after the first real integration produces reproducible evidence.
