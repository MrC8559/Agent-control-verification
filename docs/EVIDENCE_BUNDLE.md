# Evidence bundle format

ACV evidence bundles are portable JSON artifacts that record why a verification property returned `PASS`, `FAIL`, or `INCONCLUSIVE`.

The current schema version is `acv-evidence-0.1`.

## Goals

A bundle should let a reviewer inspect the result without access to the Python objects that produced it. It should also make missing evidence visible instead of silently treating it as success.

The format records:

- ACV version and commit when known;
- scenario and property identifiers;
- target, host, control, model, or framework versions when known;
- the requested action fingerprint;
- control disposition and reason code;
- a digest of control-reason text when available;
- invocation and effect fingerprints;
- audit references;
- explicit missing-evidence identifiers;
- ordered event references when the source exposes reliable ordering;
- environment metadata needed for reproduction;
- privacy metadata;
- result verdict and reason;
- a SHA-256 integrity digest over the bundle contents.

## Privacy boundary

The default format does not include raw action targets, arguments, prompts, secrets, or raw control-reason text.

The `privacy.raw_payloads_included` field is required to be `false` in schema version 0.1. The validator rejects a bundle that sets it to `true`.

This does not prove that every arbitrary metadata string is safe to publish. Callers remain responsible for keeping environment labels, component names, result reasons, audit references, redaction labels, and canary identifiers free of sensitive user data.

Hashes also need careful interpretation. A hash is useful for binding and comparison. It does not prove that the original value was safe, private, or impossible to recover from a small input space.

## Integrity

The bundle contains:

```json
"integrity": {
  "algorithm": "sha256",
  "digest": "..."
}
```

The digest is calculated over canonical JSON for every top-level field except `integrity`. `validate_evidence_bundle` recomputes the digest and rejects modified bundles.

This detects accidental or deliberate modification after the bundle was produced. It is not a digital signature and does not establish who created the bundle.

## Missing evidence

`evidence.missing` is a first-class field. A producer should add an identifier whenever an important evidence source is unavailable.

For example, the current deterministic evidence demo records:

```json
"missing": [
  "independent_invocation_evidence",
  "ordered_timeline"
]
```

This allows the saved artifact to preserve known limitations even when the verification result itself is `FAIL` or `PASS`.

## Timeline

The schema supports an ordered list of evidence references with contiguous sequence numbers. Timeline entries may refer to decisions, approvals, invocations, effects, audit events, or control failures.

A producer must not invent ordering that it did not observe. If reliable ordering is unavailable, leave the timeline empty and record that limitation in `evidence.missing`.

## CLI example

Generate a deterministic redacted bundle:

```bash
python -m agent_control_verification evidence-demo --output evidence.json
```

Validate and render it in a separate invocation:

```bash
python -m agent_control_verification render-evidence evidence.json
```

The renderer validates the schema and integrity digest before showing the verdict and supporting counts.

## Schema and validator

The machine-readable schema is stored at:

```text
schemas/evidence-bundle.schema.json
```

The Python validator is intentionally dependency-free and enforces the same core structural and integrity constraints used by ACV itself. External tooling can use the JSON Schema with its preferred standards-compliant validator.

The schema identifier is a URN. ACV does not currently claim a permanent public schema-hosting domain.

## First live evidence set

The [Codex 0.154.0 report](reports/2026-09-19-codex-0.154.0.md) links three byte-preserved live bundles and separately retains the environment-blocked attempt that could not bind an action into a bundle. A controlled-failure `FAIL` is a supported detection result, not a validation error.
