from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from typing import Any, Mapping


class ControlDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"
    DEFER = "defer"
    ERROR = "error"


class Verdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class Action:
    action_id: str
    tool: str
    target: str
    arguments: Mapping[str, Any] = field(default_factory=dict)

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "tool": self.tool,
            "target": self.target,
            "arguments": dict(self.arguments),
        }

    def fingerprint(self) -> str:
        encoded = json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class DecisionRecord:
    decision: ControlDecision
    action_id: str
    approved_fingerprint: str | None
    reason: str = ""


@dataclass(frozen=True)
class EffectRecord:
    action_id: str
    action_fingerprint: str
    tool: str
    target: str
    details: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AuditEvent:
    action_id: str
    action_fingerprint: str
    decision: ControlDecision
    message: str = ""


@dataclass(frozen=True)
class Observation:
    requested_action: Action
    decision: DecisionRecord
    effects: tuple[EffectRecord, ...]
    audit_events: tuple[AuditEvent, ...]


@dataclass(frozen=True)
class VerificationResult:
    property_name: str
    verdict: Verdict
    reason: str
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "property": self.property_name,
            "verdict": self.verdict.value,
            "reason": self.reason,
            "evidence": dict(self.evidence),
        }
