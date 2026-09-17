# Decision 0001: First real host integration

Date: 2026-09-16

Status: Accepted

## Decision

Use OpenAI Codex CLI `0.154.0` as ACV's first real host integration.

The first experiment will be narrow. It will test Codex's native tool hooks around a harmless file change in a disposable workspace and compare hook evidence with independently observed filesystem state.

This is not an ACS adapter and is not a Codex conformance claim.

## Why Codex

Codex `0.154.0` was the latest stable GitHub release when this decision was made. It was published on 2026-09-09.

Release:
https://github.com/openai/codex/releases/tag/rust-v0.154.0

The tagged source exposes native lifecycle hooks including:

- `PreToolUse`
- `PermissionRequest`
- `PostToolUse`

Source:
https://github.com/openai/codex/blob/rust-v0.154.0/codex-rs/hooks/src/lib.rs

`PreToolUseRequest` includes session, turn, tool name, tool-use identifier, and tool input. Its outcome can block execution or provide updated input.

Source:
https://github.com/openai/codex/blob/rust-v0.154.0/codex-rs/hooks/src/events/pre_tool_use.rs

`PostToolUseRequest` contains the same tool-use identifier together with tool input and tool response. This provides a useful host-side event to compare with independent effect evidence.

Source:
https://github.com/openai/codex/blob/rust-v0.154.0/codex-rs/hooks/src/events/post_tool_use.rs

The `apply_patch` handler in the pinned `0.154.0` source has both pre-tool and post-tool hook payload support. That makes it a suitable first effect surface because ACV can also verify the resulting file state without trusting Codex's own result message.

Source:
https://github.com/openai/codex/blob/rust-v0.154.0/codex-rs/core/src/tools/handlers/apply_patch.rs

## Why this is useful research

Open upstream reports show that hook coverage can vary by execution path. These reports do not prove that the same bugs are present in `0.154.0`; they show that coverage is a real property worth measuring rather than assuming.

Relevant reports:

- Code Mode `exec` missing `PreToolUse` coverage: https://github.com/openai/codex/issues/23411
- nested Code Mode shell results missing `PostToolUse` coverage on a reported Windows build: https://github.com/openai/codex/issues/38850
- user-level `PostToolUse` discovery inconsistency in an earlier CLI release: https://github.com/openai/codex/issues/24211

ACV is designed for this class of question. A hook being configured, trusted, or visible is not sufficient evidence that every relevant effect path is governed by it.

## Overlap with OWASP work

The OWASP Agent Control Standard project already has work around a Codex reference adapter:

https://github.com/GenAI-Security-Project/agent-control-standard/issues/89

ACV will not duplicate that work. The first Codex integration will use Codex's native hook contract and test whether a decision corresponds to the observed effect. It will not translate Codex events into ACS or claim ACS conformance.

If ACV discovers a reproducible host issue, the result can be reported upstream with a minimal fixture and evidence bundle.

## Alternatives considered

### OpenCode

OpenCode V2 exposes permission evaluation, before-tool, after-tool, and shell hooks. It is open source and suitable for automated testing.

Official plugin documentation:
https://opencode.ai/v2/docs/build/plugins

It remains a strong second integration. It was not selected first because its V2 plugin surface is currently in active migration and OWASP ACS already has recent OpenCode dogfooding work. ACV should avoid duplicating that coverage until its own effect-verification adapter is established.

### Cursor

Cursor has a strong hook surface including `preToolUse`, `postToolUse`, shell hooks, MCP hooks, and documented fail-open behaviour for some hook failures.

Official documentation:
https://cursor.com/docs/hooks

This is useful for ACV's failure-posture work. It was not selected first because the host is proprietary and less convenient for a reproducible open-source integration test environment. It remains a good later target.

### Claude Code

Claude Code has mature tool and permission hooks and would support the same class of experiments. It was not selected first because current OWASP ACS work already contains substantial Claude Code dogfooding and host-behaviour investigation. ACV should add distinct evidence rather than repeat that work.

## First properties to test

### 1. Pre-tool denial prevents a file effect

Configure an ACV-owned `PreToolUse` hook for a controlled `apply_patch` action.

The hook records the incoming event and denies the action. ACV snapshots the disposable workspace before and after the Codex run.

Expected result:

- hook evidence records the denial;
- the target file is unchanged;
- ACV returns `PASS` only when both facts are available.

A denial with a changed file is `FAIL`.

Missing effect evidence is `INCONCLUSIVE`.

### 2. Allowed execution matches the requested effect

Allow one controlled patch. Record pre-tool and post-tool evidence, then compare it with the filesystem change.

The experiment should preserve the Codex tool-use identifier so pre and post events can be paired.

### 3. Hook failure posture is observable

Use a controlled fixture that produces an unusable hook response or exits unexpectedly. Record whether Codex attempts the tool and whether the file changes.

The configured or observed host behaviour is evidence. ACV must not label an ungoverned invocation as `PASS` merely because proceeding was expected.

### 4. Coverage is measured per tool path

Do not infer that because `apply_patch` is covered, Code Mode, shell execution, MCP, or other tools are covered too. Each execution path needs its own evidence before ACV reports it as observed.

## Smallest end-to-end experiment

1. Pin Codex CLI to `0.154.0`.
2. Create a disposable local workspace containing one marker file.
3. Configure an ACV-owned `PreToolUse` hook for the relevant `apply_patch` matcher.
4. Ask Codex to make a deterministic change to the marker file.
5. Capture the hook event and decision to a local evidence directory.
6. Snapshot the filesystem before and after the run from outside the hook process.
7. Produce an `acv-evidence-0.1` bundle containing the exact Codex version, property, control evidence, effect fingerprint, and any missing evidence.
8. Repeat with an allowed action and a controlled hook-failure case.

## Safety boundary

The first integration must remain local and disposable.

- Use a temporary workspace.
- Use harmless marker files only.
- Do not test third-party targets.
- Do not require real secrets in fixtures or evidence.
- Do not make network access part of the first experiment.
- Do not treat Codex's own tool result as independent proof of the file effect.

## Evidence required before broadening scope

The first Codex adapter is successful when ACV can reproduce at least one denial case and one allowed case while independently observing filesystem state and preserving version-pinned evidence.

Only after that should the project test additional Codex tool paths or compare host versions.
