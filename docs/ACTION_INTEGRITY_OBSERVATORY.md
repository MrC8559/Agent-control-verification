# Agent Action Integrity Observatory

The Agent Action Integrity Observatory is the broader research programme around Agent Control Verification (ACV).

ACV remains the verification engine. Its job is to turn narrow security claims into falsifiable properties backed by evidence. The Observatory is the publication and research layer that can accumulate those measurements across exact host versions and execution paths over time.

The distinction matters. ACV should stay small enough that its verification semantics remain reviewable. The Observatory should grow only when ACV has real, reproducible observations to publish.

## Research question

The Observatory is built around one question:

> When an autonomous system reports that an action was allowed, denied, modified, approved, blocked, or failed, does independently observable evidence agree with that control outcome?

The verifier should avoid treating the agent, host, hook, policy engine, or audit log as the sole source of truth when an independent effect surface is available.

## What counts as an observation

An Observatory observation should be narrower than a product verdict.

Each published observation should identify at least:

- the host or agent product;
- the exact observed host version;
- the execution path or tool surface;
- the ACV property being tested;
- the resulting `PASS`, `FAIL`, or `INCONCLUSIVE` verdict;
- the ACV version or commit that produced the evidence;
- the evidence-bundle format and integrity digest;
- the observation date and relevant runtime/environment provenance;
- the exact limitations and untested paths;
- reproduction instructions or the evidence report that contains them.

A single observation must not be generalized to unrelated tools, versions, hosts, models, or execution paths.

## Publication rules

The Observatory should preserve the evidence discipline already used by ACV:

1. No aggregate security score.
2. No host-wide conclusion from one execution path.
3. Missing or contradictory evidence remains `INCONCLUSIVE`.
4. Independently observed effects are preferred over target self-report where possible.
5. Historical observations should remain immutable once published. Corrections should use explicit superseding records rather than silent rewriting.
6. Standards may define useful properties, but an ACV observation is not certification or conformance unless an external process establishes that separately.
7. Evidence is redacted by default and uses synthetic/local effects unless a later experiment has a separately documented safety boundary.

## Relationship to ACV

ACV currently provides the deterministic core needed for the first Observatory observation:

- decision/effect separation;
- action fingerprints;
- independent filesystem observation;
- approval binding, freshness, and replay checks;
- explicit control-failure posture;
- `PASS`, `FAIL`, and `INCONCLUSIVE` semantics;
- versioned redacted evidence bundles;
- a version-pinned Codex `0.154.0` probe path.

The Observatory should not weaken these semantics for the sake of coverage or presentation.

## First observation gate

The first Observatory observation does not exist yet.

The current gate is ACV `v0.1.0`: capture real Codex CLI `0.154.0` evidence for the narrow `apply_patch` path using separate deny, allow, and controlled hook-failure cases, with the marker-file effect observed independently.

Only after that evidence is captured, validated, and documented should the repository add a formal observation index. That follow-up is tracked in issue #29.

The first published record should therefore be boringly specific. It should say exactly what was observed, on which version and path, with which property and evidence. It should also say what was not tested.

## Possible later expansion

After the first observation proves the method against a real host, the programme can expand one measured surface at a time. Candidate directions already under research include:

- deny behaviour across retry and escalation paths;
- control-authorized action modification;
- delegated-agent scope and attribution;
- integrity of the active control plane;
- MCP credential audience binding and token non-passthrough;
- additional execution paths on the same host;
- additional agent hosts where comparable evidence can be obtained.

Each direction must earn its place through a measurable property and an independent observation strategy. Broad feature expansion is not a substitute for evidence.

## Current status

Research programme defined. No Observatory dataset or cross-host matrix is published yet.

The next meaningful event is the first complete ACV live-host evidence report.
