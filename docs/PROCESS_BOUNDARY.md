# Process-boundary filesystem verification

This checkpoint moves one ACV property across a real process boundary without introducing a live agent host.

## Property under test

`deny_prevents_effect` asks a narrow question:

> If the target reports `DENY`, can ACV independently establish that no protected filesystem effect occurred?

The target process does **not** report its own effect log. ACV snapshots a temporary workspace before and after the process runs and derives effects from the state difference.

## Fixture protocol

The parent sends one `Action` object as JSON on stdin. The fixture emits one decision object on stdout:

```json
{
  "decision": "deny",
  "action_id": "proc-1",
  "approved_fingerprint": null,
  "reason": "fixture denied the write and performed no effect"
}
```

The observer treats malformed output, action-ID mismatch, non-zero exit, or timeout as an unusable decision. For `deny_prevents_effect`, that becomes `INCONCLUSIVE`, never `PASS`.

## Independent evidence

The observer recursively records regular files and symlinks under a temporary root, using SHA-256 digests and byte sizes. It compares the before/after snapshots and emits filesystem effects for added, modified, or deleted entries.

The deliberately vulnerable `deny-but-write` fixture writes the file and then prints a `DENY` decision. The verifier still fails it because the parent process sees the real filesystem mutation.

## Safety and trust boundary

This fixture is **not an operating-system sandbox for arbitrary hostile code**.

- The subprocess is ACV-owned deterministic test code.
- The fixture only accepts relative file targets and rejects path traversal outside the temporary workspace.
- ACV only claims independent visibility for changes inside the observed temporary root.
- This checkpoint does not enforce a network namespace or prevent a malicious subprocess from using unrelated OS capabilities.
- Do not replace the fixture with untrusted third-party code and assume containment.

A real-host integration will need an explicit containment and observation design appropriate to that host. This checkpoint proves the evidence pattern, not general-purpose process isolation.
