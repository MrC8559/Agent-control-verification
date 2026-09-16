# Roadmap

The roadmap is evidence-led. A milestone is not complete because the code exists; it is complete when the security property can be demonstrated reproducibly.

## v0.0.1: decision/effect proof

Goal: prove that the verifier can distinguish a secure control boundary from one that only *claims* to block an action.

- [x] Action fingerprint
- [x] Decision record
- [x] Synthetic effect log
- [x] Audit evidence
- [x] `deny_prevents_effect`
- [x] `allow_binds_exact_action`
- [x] `consequential_effect_is_audited`
- [x] Vulnerable and hardened demo targets
- [x] Deterministic tests and CI

## v0.0.2: approvals and failure posture

- [ ] Bind approval to exact action fingerprint
- [ ] Detect approval replay
- [ ] Model control unavailable / timeout
- [ ] Distinguish refusal from transport failure
- [ ] Require explicit evidence for fail-open behavior
- [ ] Add PASS / FAIL / INCONCLUSIVE JSON report schema

## v0.0.3: evidence bundles

- [ ] Reproducible run manifest
- [ ] Host/framework/control versions
- [ ] Environment fingerprint
- [ ] Ordered decision, invocation, and effect trace
- [ ] Redacted evidence export
- [ ] JUnit/SARIF output where semantically appropriate

## v0.1.0: first real integration

- [ ] Select one real agent host/control boundary
- [ ] Build a narrow adapter
- [ ] Reproduce synthetic invariants against the real host
- [ ] Document unsupported/untestable properties explicitly
- [ ] Publish a version-pinned conformance-style report without claiming certification

## Later

Potential directions include cross-host matrices, MCP tool boundaries, identity/privilege scope, multi-agent delegation, continuous regression testing, and hosted private evidence storage.
