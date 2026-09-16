# Reviewer guide

This file is a short path through Agent Control Verification for someone evaluating the project as security research or engineering work.

ACV is intentionally narrow. The central claim is not that agent systems are broadly insecure. It is that a control decision and the resulting effect are separate facts and should be verified separately where the environment allows it.

## Ten-minute review

### 1. Start with the thesis

Read [`README.md`](README.md), especially:

- the decision/effect distinction;
- the current Codex milestone;
- the explicit scope and limitations.

### 2. Inspect the trust model

Read:

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- [`docs/PROCESS_BOUNDARY.md`](docs/PROCESS_BOUNDARY.md)
- [`docs/APPROVAL_MODEL.md`](docs/APPROVAL_MODEL.md)
- [`docs/FAILURE_POSTURE.md`](docs/FAILURE_POSTURE.md)

These documents explain what ACV trusts, what it tries to observe independently, and when evidence is insufficient for `PASS`.

### 3. Look at the falsifiable properties

Useful test files include:

- [`tests/test_verifier.py`](tests/test_verifier.py)
- [`tests/test_process_observer.py`](tests/test_process_observer.py)
- [`tests/test_approval.py`](tests/test_approval.py)
- [`tests/test_failure.py`](tests/test_failure.py)

The deliberately vulnerable fixtures are intentional. A failing target can be a successful test of the verifier.

### 4. Inspect the evidence model

Read:

- [`docs/EVIDENCE_BUNDLE.md`](docs/EVIDENCE_BUNDLE.md)
- [`schemas/evidence-bundle.schema.json`](schemas/evidence-bundle.schema.json)
- [`tests/test_evidence.py`](tests/test_evidence.py)

ACV treats `INCONCLUSIVE` as a first-class result when evidence is missing or contradictory. Evidence bundles are redacted by default and include an integrity digest, but the digest is not presented as an attestation of who produced the evidence.

### 5. Inspect the real-host boundary

The first pinned real host is Codex CLI `0.154.0`.

Read:

- [`docs/CODEX_PROBE.md`](docs/CODEX_PROBE.md)
- [`docs/decisions/0001-first-real-host-codex.md`](docs/decisions/0001-first-real-host-codex.md)
- [`tests/test_codex_integration.py`](tests/test_codex_integration.py)
- [`tests/test_codex_evidence.py`](tests/test_codex_evidence.py)
- [`tests/test_codex_evidence_guard.py`](tests/test_codex_evidence_guard.py)

The adapter, disposable workspace, redacted hook recorder, and evidence collector are implemented. A live version-pinned Codex evidence report has not yet been published, so the project does not claim that the real-host milestone is complete.

## What this repository is intended to demonstrate

- security claims expressed as falsifiable properties;
- independent observation where practical instead of relying only on self-report;
- exact authorization binding and replay/freshness checks;
- explicit modelling of fail-open and control-failure behaviour;
- preserved uncertainty through `PASS`, `FAIL`, and `INCONCLUSIVE`;
- version-pinned experiments and reproducible evidence artifacts;
- conservative claims and documented trust boundaries;
- safe local fixtures rather than uncontrolled third-party testing.

## Maintainer

ACV is maintained by Charlie B, an independent builder working across agent security, AI systems, production financial software, and evidence-driven research.

Other work includes [ChainTax](https://chaintax.co.uk), a live UK crypto-tax product, plus private quantitative and research infrastructure.

Current areas of interest include remote roles in agent security, AI infrastructure, applied AI, research engineering, and security engineering for autonomous or tool-using systems.
