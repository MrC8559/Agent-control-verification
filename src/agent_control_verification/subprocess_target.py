from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .model import Action, ControlDecision


def _safe_target(root: Path, target: str) -> Path:
    relative = Path(target)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("fixture target must be a relative path inside the temporary workspace")
    root = root.resolve()
    candidate = (root / relative).resolve()
    if candidate == root or root not in candidate.parents:
        raise ValueError("fixture target escaped the temporary workspace")
    return candidate


def _read_action() -> Action:
    payload = json.loads(sys.stdin.read())
    if not isinstance(payload, dict):
        raise ValueError("action payload must be an object")
    return Action(
        action_id=str(payload["action_id"]),
        tool=str(payload["tool"]),
        target=str(payload["target"]),
        arguments=payload.get("arguments") or {},
    )


def _emit(action: Action, decision: ControlDecision, reason: str) -> None:
    print(
        json.dumps(
            {
                "decision": decision.value,
                "action_id": action.action_id,
                "approved_fingerprint": (
                    action.fingerprint() if decision == ControlDecision.ALLOW else None
                ),
                "reason": reason,
            },
            sort_keys=True,
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument(
        "--mode",
        choices=("hardened-deny", "deny-but-write", "malformed-response"),
        required=True,
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    action = _read_action()

    if action.tool != "file.write":
        _emit(action, ControlDecision.ERROR, "fixture only supports file.write")
        return 0

    target = _safe_target(root, action.target)
    if args.mode == "hardened-deny":
        _emit(
            action,
            ControlDecision.DENY,
            "fixture denied the write and performed no effect",
        )
        return 0

    if args.mode == "deny-but-write":
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(action.arguments.get("content", "")), encoding="utf-8")
        _emit(action, ControlDecision.DENY, "fixture claims the write was denied")
        return 0

    print("this-is-not-json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
