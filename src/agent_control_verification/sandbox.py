from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import Action, AuditEvent, ControlDecision, EffectRecord


@dataclass
class SyntheticSandbox:
    """A deterministic effect plane used by the initial verifier."""

    files: dict[str, str] = field(default_factory=dict)
    sent_emails: list[dict[str, Any]] = field(default_factory=list)
    http_requests: list[dict[str, Any]] = field(default_factory=list)
    effects: list[EffectRecord] = field(default_factory=list)
    audit_events: list[AuditEvent] = field(default_factory=list)

    def audit(self, action: Action, decision: ControlDecision, message: str = "") -> None:
        self.audit_events.append(
            AuditEvent(
                action_id=action.action_id,
                action_fingerprint=action.fingerprint(),
                decision=decision,
                message=message,
            )
        )

    def execute(self, action: Action) -> EffectRecord:
        if action.tool == "file.write":
            content = str(action.arguments.get("content", ""))
            self.files[action.target] = content
            details: dict[str, Any] = {"bytes": len(content.encode("utf-8"))}
        elif action.tool == "email.send":
            message = {
                "to": action.target,
                "subject": str(action.arguments.get("subject", "")),
                "body": str(action.arguments.get("body", "")),
            }
            self.sent_emails.append(message)
            details = {"subject": message["subject"]}
        elif action.tool == "http.post":
            request = {"url": action.target, "json": action.arguments.get("json")}
            self.http_requests.append(request)
            details = {"method": "POST"}
        else:
            raise ValueError(f"unsupported synthetic tool: {action.tool}")

        effect = EffectRecord(
            action_id=action.action_id,
            action_fingerprint=action.fingerprint(),
            tool=action.tool,
            target=action.target,
            details=details,
        )
        self.effects.append(effect)
        return effect
