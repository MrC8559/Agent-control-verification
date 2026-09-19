# Roadmap

ACV develops through evidence checkpoints rather than feature count. A milestone is complete only when the security property can be demonstrated reproducibly from the evidence available to the verifier.

## Current position

- `v0.0.1` decision/effect proof: complete
- `v0.0.2` independent effects, approvals, and failure posture: complete
- `v0.0.3` evidence-bundle core: substantially complete
- `v0.1.0` first real host integration: evidence complete; closeout published; final release pending

The four preserved outcomes and scope limits are documented in the [final evidence report](docs/reports/2026-09-19-codex-0.154.0.md). The reviewed closeout is published. Package metadata is prepared as `0.1.0`; final commit, CI, tag and release steps remain pending. No further live experiment is required for this milestone.

See [`docs/PUBLIC_STATUS.md`](docs/PUBLIC_STATUS.md) for the short public checkpoint and [`docs/CODEX_PROBE.md`](docs/CODEX_PROBE.md) for the runnable experiment.

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

Goal: stop trusting the target as the only source of truth and make common authorization failures explicit.

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
- [x] Add stable `PASS`, `FAIL`, and `INCONCLUSIVE` result serialization

## v0.0.3: Evidence bundles

Goal: make results portable enough to save, inspect, validate, and compare without trusting the original in-memory objects.

- [x] Versioned reproducible evidence artifact
- [x] Host, framework, target, and control version fields
- [x] Environment metadata
- [x] Explicit missing-evidence fields
- [x] Redacted-by-default evidence export
- [x] Bundle integrity digest and validation
- [x] Independent saved-bundle renderer
- [x] Populate ordered decision, invocation, and effect traces from the measured Codex hook source and independent collection-time effect observation
- [ ] Add JUnit or SARIF output where the semantics are useful and do not flatten uncertainty

## v0.1.0: First real integration

Goal: demonstrate ACV against one real, version-pinned agent host without expanding the claim beyond the exact path observed.

Pinned host: Codex CLI `0.154.0`.

- [x] Select the first host and record the decision ([Decision 0001](docs/decisions/0001-first-real-host-codex.md))
- [x] Build a narrow Codex native-hook adapter
- [x] Build a disposable probe workspace generator
- [x] Record redacted `PreToolUse` and `PostToolUse` evidence
- [x] Build an evidence collector that independently reads marker-file state
- [x] Add deterministic deny, allow, malformed-output, and hook-exit fixtures
- [x] Run the deny case against a real Codex `0.154.0` session
- [x] Verify the denied `apply_patch` against independent filesystem state
- [x] Run the allow case and pair pre/post hook evidence
- [x] Verify the expected allowed file effect independently
- [x] Measure one controlled hook-failure case and preserve the observed host posture
- [x] Record exact observed host, runtime, adapter, and evidence versions
- [x] Document unsupported or untested Codex tool paths explicitly
- [x] Prepare the consolidated version-pinned evidence report and validated redacted artifacts without claiming certification
- [x] Publish the reviewed closeout (administrative follow-up; no further experiment required)

The milestone is complete only when the saved evidence can be inspected independently and the result remains appropriately scoped to the observed Codex version and tool path.

## v0.2.0: Broaden one host carefully

Planned only after `v0.1.0` produces reproducible live evidence.

Potential work:

- test additional Codex execution paths separately rather than inheriting coverage from `apply_patch`;
- measure shell or command execution boundaries where independent observation is possible;
- investigate Code Mode paths as distinct surfaces;
- test MCP tool boundaries with synthetic local servers;
- preserve per-path coverage and explicit unknowns;
- compare behaviour across pinned Codex versions when there is a concrete reason to do so.

No item in this milestone should turn absence of evidence into a coverage claim.

## v0.3.0: Cross-host evidence matrix

Goal: determine whether the same ACV properties can be measured consistently across more than one agent host.

Potential candidates include OpenCode, Claude Code, and Cursor, subject to current interfaces and reproducibility at the time of implementation.

Potential work:

- define a host-adapter contract around decision, invocation, effect, and failure evidence;
- add a second host with the smallest comparable effect surface;
- compare which evidence is independently observable on each host;
- keep host-specific limitations visible instead of reducing them to a single security score;
- publish version-pinned comparison artifacts rather than broad product rankings.

## v0.4.0: Regression and CI use

Goal: make verified properties useful as repeatable engineering checks.

Potential work:

- stable machine-readable regression output;
- JUnit and SARIF exports where the meaning remains faithful to `PASS`, `FAIL`, and `INCONCLUSIVE`;
- scenario manifests for repeatable host/version combinations;
- CI workflows for approved local or disposable test environments;
- evidence retention and comparison between runs;
- clear detection of a property that changes from `PASS` to `FAIL` or `INCONCLUSIVE` after a host update.

## Longer-term research

Possible directions include:

- identity and privilege scope;
- approval authority across delegated agents;
- multi-agent delegation and confused-deputy cases;
- MCP authorization and tool-boundary evidence;
- secret-access and data-egress effects using synthetic canaries;
- continuous host-version regression testing;
- private evidence storage for environments where even redacted artifacts require controlled access.

These are research directions, not promises. The roadmap should change when evidence shows that a proposed property is not measurable or that another project already covers it better.
