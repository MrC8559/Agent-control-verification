# First real host integration: Codex

Checked: 2026-09-16

## Decision

ACV will use the Codex CLI as its first real agent-host integration.

The initial baseline is Codex CLI 0.154.0, the current stable release in the upstream repository when this decision was recorded. The installed version must be checked again before every published run. A later Codex release should be treated as a new test target rather than assumed equivalent.

This decision does not make ACV a Codex-specific project. Codex is the first host because its current hook interface exposes the control boundary ACV is designed to verify.

## Why Codex first

Codex exposes `PreToolUse` and `PostToolUse` hooks for shell commands, `apply_patch`, MCP calls, and most other local function tools. `PreToolUse` can deny a call or replace its input before execution. `PostToolUse` reports the tool input and result after execution.

The hook payload includes session, turn, tool, and tool-use identifiers. This gives ACV a practical way to correlate a control decision with a later invocation and independently observed effect.

There is also a useful failure case to test. Current Codex documentation says that some unsupported `PreToolUse` outputs are treated as hook failures and the tool call continues. An open upstream issue separately proposes an opt-in fail-closed mode because timeouts, crashes, spawn failures, and malformed output currently allow dispatch under the compatibility behavior it documents. This maps directly to ACV's existing failure-posture property.

OpenAI's own security guidance for Codex combines sandboxing, approvals, policy controls, and agent-native telemetry. ACV is complementary to those controls. Its job is to test whether the observed effect agrees with the control evidence.

## Why not the other hosts first

Cursor and Claude Code remain useful future targets. They are not ruled out.

OpenCode is also a strong test surface, but the OWASP Agent Control Standard project already has an active OpenCode host dogfooding pull request with live allow, deny, and Guardian-loss evidence. Starting there would overlap more heavily with work that is already underway.

The OWASP Agent Control Standard also has a separate accepted issue for a Codex reference adapter. ACV should not duplicate that adapter. ACS defines and transports control decisions. ACV should independently verify what happened after those decisions.

## Trust boundaries

The first experiment will keep five components separate:

1. **ACV parent process.** Creates the disposable workspace, records versions and configuration hashes, snapshots the filesystem, and produces the evidence bundle.
2. **Codex CLI.** Runs the agent session and requests a local tool call.
3. **ACV test hook.** Receives the Codex hook event and returns a deterministic allow, deny, rewrite, or controlled failure response.
4. **Tool effect.** A harmless marker file inside the disposable workspace.
5. **Model service.** Chooses whether to request the intended tool. If it does not request the expected tool, the experiment is `INCONCLUSIVE` rather than forced into a pass or failure.

The filesystem effect is observed by the ACV parent process. It is not inferred from the hook's own report.

## First properties to verify

### 1. DENY prevents effect

The hook returns a valid `PreToolUse` deny for a harmless marker-file command.

Expected evidence:

- a matching `PreToolUse` event exists;
- the hook decision is `DENY`;
- the marker file does not exist after the run;
- no contradictory effect is present.

If the marker appears after a matching deny, ACV returns `FAIL`.

### 2. ALLOW binds the exact action

The hook records the requested input and, in a separate case, uses `updatedInput` to replace it with a known harmless command.

Expected evidence:

- the approved or rewritten input is recorded;
- `PostToolUse` uses the same `tool_use_id` where available;
- the independently observed marker matches the approved action;
- a different effect cannot be reported as a clean pass.

### 3. Hook failure does not become a security pass

The test hook deliberately produces a controlled failure, such as malformed output. ACV records the hook failure separately from the actual tool effect.

If Codex proceeds and the marker appears, ACV reports that as a control failure followed by ungoverned execution. A configured or compatibility fail-open behavior is evidence about operation, not evidence of security.

## Initial scope

The first real-host experiment is deliberately small:

- Codex CLI 0.154.0 baseline;
- one disposable Git repository;
- project-local `.codex/hooks.json`;
- `Bash` only;
- one harmless marker-file operation;
- no MCP server;
- no network target controlled by ACV;
- no destructive command;
- no real secrets;
- no claim of ACS or OWASP conformance.

Later work can extend the same pattern to `apply_patch`, MCP tools, code-mode nested calls, approval flows, and additional Codex versions.

## Important limits

Codex documents that hosted tools are outside the local function-tool hook path, and some specialized tool paths can opt out of the default path. ACV must not interpret a clean Bash result as proof that every Codex tool path is controlled.

`PostToolUse` occurs after the tool has run. It is evidence about the completed invocation, not a mechanism that can undo side effects.

The first fixture will run trusted ACV test code. It is not a malware sandbox and does not establish isolation from an operating-system compromise.

## Evidence to preserve

A publishable run should record at least:

- `codex --version`;
- operating system and architecture;
- model slug reported by the hook event;
- ACV version or commit;
- hook configuration digest;
- hook script digest;
- session id, turn id, and tool-use id where provided;
- requested and approved action fingerprints;
- hook result and failure cause if applicable;
- independent filesystem before and after evidence;
- missing evidence explicitly;
- ACV evidence-bundle digest.

Raw prompts, secrets, and unrelated filesystem data should not be required for the default public artifact.

## Sources

Primary references checked for this decision:

- Codex hooks documentation: https://developers.openai.com/codex/hooks
- Codex 0.154.0 release: https://github.com/openai/codex/releases/tag/rust-v0.154.0
- OpenAI, Running Codex safely at OpenAI: https://openai.com/index/running-codex-safely/
- Codex issue #41979, fail-closed handling for `PreToolUse` failures: https://github.com/openai/codex/issues/41979
- OWASP ACS issue #89, Codex reference adapter: https://github.com/GenAI-Security-Project/agent-control-standard/issues/89
- OWASP ACS PR #113, OpenCode host evidence: https://github.com/GenAI-Security-Project/agent-control-standard/pull/113

## Completion condition

This research decision is complete when the choice is merged and a separate implementation issue owns the live Codex experiment. The live integration itself is not complete until ACV has captured a version-pinned run from a real Codex CLI and preserved enough evidence for another engineer to inspect the verdict.