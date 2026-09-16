# Roadmap

The roadmap is evidence-led. A milestone is complete only when the security property can be demonstrated reproducibly.

## v0.0.1: Decision/effect proof

Goal: prove that the verifier can distinguish a secure control boundary from one that only claims to block an action.

- [x] Action fingerprint
- [x] Decision record
- [x] Synthetic effect log
- [x] Audit evidence
- [x] `deny_prevents_effect`
- [x] `allow_binds_exact_action`
- [x] `consequential_effect_is_audited`
- [x] Vulnerable and hardened demo targets
- [x] Deterministic tests and CI

## v0.0.2: Independent effects, approvals, and failure posture

- [x] Observe added, modified, and deleted files independently across a subprocess boundary
- [x] Catch a target that reports `DENY` after performing the file effect
- [x] Return `INCONCLUSIVE` rather than `PASS` for malformed subprocess decision evidence
- [x] Bind approval to principal, session, tool, target, and arguments
- [x] Detect single-use approval replay
- [x] Reject cross-identity, cross-session, and cross-tool approval reuse
- [x] Verify approval freshness and make missing freshness or consumption evidence `INCONCLUSIVE`
- [x] Model control unavailable and timeout cases
- [x] Distinguish policy deny, security refusal, timeout, transport loss, and malformed response
- [x] Require explicit invocation and effect evidence for fail-open behaviour
- [ ] Add a stable `PASS` / `FAIL` / `INCONCLUSIVE` JSON report schema

## v0.0.3: Evidence bundles

- [ ] Reproducible run manifest
- [ ] Host, framework, and control versions
- [ ] Environment fingerprint
- [ ] Ordered decision, invocation, and effect trace
- [ ] Redacted evidence export
- [ ] JUnit or SARIF output where semantically appropriate

## v0.1.0: First real integration

- [ ] Select one real agent host/control boundary
- [ ] Build a narrow adapter
- [ ] Reproduce synthetic invariants against the real host
- [ ] Document unsupported or untestable properties explicitly
- [ ] Publish a version-pinned conformance-style report without claiming certification

## Later

Potential directions include cross-host matrices, MCP tool boundaries, identity and privilege scope, multi-agent delegation, continuous regression testing, and hosted private evidence storage.
