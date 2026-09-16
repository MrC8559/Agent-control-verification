from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Mapping

from .model import Action, ControlDecision, DecisionRecord, EffectRecord, Observation


@dataclass(frozen=True)
class FileState:
    kind: str
    digest: str
    size: int


@dataclass(frozen=True)
class ProcessRunMetadata:
    returncode: int | None
    timed_out: bool
    stdout: str
    stderr: str


@dataclass(frozen=True)
class ProcessObservation:
    observation: Observation
    metadata: ProcessRunMetadata


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def snapshot_filesystem(root: Path) -> dict[str, FileState]:
    root = root.resolve()
    state: dict[str, FileState] = {}
    if not root.exists():
        return state

    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            target = os.readlink(path).encode("utf-8", errors="surrogateescape")
            state[relative] = FileState("symlink", _digest_bytes(target), len(target))
        elif path.is_file():
            data = path.read_bytes()
            state[relative] = FileState("file", _digest_bytes(data), len(data))
    return state


def _effects_from_diff(
    action: Action,
    before: Mapping[str, FileState],
    after: Mapping[str, FileState],
) -> tuple[EffectRecord, ...]:
    effects: list[EffectRecord] = []
    for path in sorted(set(before) | set(after)):
        old = before.get(path)
        new = after.get(path)
        if old == new:
            continue
        if old is None:
            change = "added"
        elif new is None:
            change = "deleted"
        else:
            change = "modified"
        effects.append(
            EffectRecord(
                action_id=action.action_id,
                action_fingerprint=action.fingerprint(),
                tool="filesystem.observed",
                target=path,
                details={
                    "source": "independent_filesystem_snapshot",
                    "change": change,
                    "before_digest": old.digest if old else None,
                    "after_digest": new.digest if new else None,
                    "before_size": old.size if old else None,
                    "after_size": new.size if new else None,
                },
            )
        )
    return tuple(effects)


def _error_decision(action: Action, reason: str) -> DecisionRecord:
    return DecisionRecord(ControlDecision.ERROR, action.action_id, None, reason)


def _parse_decision(action: Action, stdout: str, returncode: int) -> DecisionRecord:
    if returncode != 0:
        return _error_decision(action, f"target exited with status {returncode}")
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return _error_decision(action, "target did not emit one valid JSON decision")
    if not isinstance(payload, dict):
        return _error_decision(action, "target decision payload was not an object")
    if payload.get("action_id") != action.action_id:
        return _error_decision(action, "target decision action_id did not match request")
    try:
        decision = ControlDecision(payload["decision"])
    except (KeyError, ValueError, TypeError):
        return _error_decision(action, "target decision value was missing or invalid")
    approved = payload.get("approved_fingerprint")
    if approved is not None and not isinstance(approved, str):
        return _error_decision(action, "approved_fingerprint was not a string or null")
    reason = payload.get("reason", "")
    if not isinstance(reason, str):
        return _error_decision(action, "target decision reason was not a string")
    return DecisionRecord(decision, action.action_id, approved, reason)


def observe_subprocess_filesystem_run(
    action: Action,
    root: Path,
    *,
    mode: str,
    timeout_seconds: float = 5.0,
) -> ProcessObservation:
    root.mkdir(parents=True, exist_ok=True)
    root = root.resolve()
    before = snapshot_filesystem(root)
    command = [
        sys.executable,
        "-m",
        "agent_control_verification.subprocess_target",
        "--root",
        str(root),
        "--mode",
        mode,
    ]
    env = os.environ.copy()
    env["ACV_SUBPROCESS_FIXTURE"] = "1"
    try:
        completed = subprocess.run(
            command,
            input=json.dumps(action.canonical_payload()),
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            cwd=root,
            env=env,
            check=False,
        )
        metadata = ProcessRunMetadata(
            completed.returncode,
            False,
            completed.stdout,
            completed.stderr,
        )
        decision = _parse_decision(action, completed.stdout, completed.returncode)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        metadata = ProcessRunMetadata(None, True, stdout, stderr)
        decision = _error_decision(
            action,
            "target timed out before a usable decision was observed",
        )

    after = snapshot_filesystem(root)
    effects = _effects_from_diff(action, before, after)
    return ProcessObservation(
        Observation(action, decision, effects, ()),
        metadata,
    )
