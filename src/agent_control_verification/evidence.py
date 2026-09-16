from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Iterable, Mapping, Sequence

from .model import ControlDecision, Verdict, VerificationResult


SCHEMA_VERSION = "acv-evidence-0.1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TOP_LEVEL_KEYS = {
    "schema_version",
    "bundle_id",
    "created_at",
    "producer",
    "scenario",
    "components",
    "action",
    "control",
    "evidence",
    "environment",
    "privacy",
    "result",
    "integrity",
}
_COMPONENT_ROLES = {"target", "host", "control", "model", "framework"}
_EVENT_KINDS = {"decision", "approval", "invocation", "effect", "audit", "control_failure"}
_CONTROL_DECISIONS = {decision.value for decision in ControlDecision} | {"unknown"}
_VERDICTS = {verdict.value for verdict in Verdict}


class EvidenceValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ComponentVersion:
    role: str
    name: str
    version: str | None = None
    commit: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return {
            "role": self.role,
            "name": self.name,
            "version": self.version,
            "commit": self.commit,
        }


@dataclass(frozen=True)
class EvidenceEvent:
    sequence: int
    kind: str
    ref: str
    timestamp: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "kind": self.kind,
            "ref": self.ref,
            "timestamp": _format_time(self.timestamp) if self.timestamp else None,
        }


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _format_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise EvidenceValidationError("timestamps must include a timezone")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise EvidenceValidationError(f"{path} must be a non-empty ISO-8601 string")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise EvidenceValidationError(f"{path} is not valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceValidationError(f"{path} must include a timezone")
    return parsed


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_bundle_digest(bundle: Mapping[str, Any]) -> str:
    payload = {key: value for key, value in bundle.items() if key != "integrity"}
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _require_mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EvidenceValidationError(f"{path} must be an object")
    return value


def _require_nonempty_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceValidationError(f"{path} must be a non-empty string")
    return value


def _require_optional_string(value: Any, path: str) -> str | None:
    if value is None:
        return None
    return _require_nonempty_string(value, path)


def _require_string_list(value: Any, path: str) -> list[str]:
    if not isinstance(value, list):
        raise EvidenceValidationError(f"{path} must be an array")
    items: list[str] = []
    for index, item in enumerate(value):
        items.append(_require_nonempty_string(item, f"{path}[{index}]"))
    return items


def _require_sha256(value: Any, path: str) -> str:
    digest = _require_nonempty_string(value, path)
    if not _SHA256_RE.fullmatch(digest):
        raise EvidenceValidationError(f"{path} must be a lowercase SHA-256 hex digest")
    return digest


def validate_evidence_bundle(bundle: Mapping[str, Any]) -> None:
    root = _require_mapping(bundle, "bundle")
    keys = set(root)
    missing_keys = sorted(_TOP_LEVEL_KEYS - keys)
    extra_keys = sorted(keys - _TOP_LEVEL_KEYS)
    if missing_keys:
        raise EvidenceValidationError(f"bundle is missing required keys: {', '.join(missing_keys)}")
    if extra_keys:
        raise EvidenceValidationError(f"bundle contains unknown keys: {', '.join(extra_keys)}")

    if root["schema_version"] != SCHEMA_VERSION:
        raise EvidenceValidationError(f"unsupported schema_version: {root['schema_version']!r}")

    _require_nonempty_string(root["bundle_id"], "bundle.bundle_id")
    _parse_time(root["created_at"], "bundle.created_at")

    producer = _require_mapping(root["producer"], "bundle.producer")
    if set(producer) != {"name", "version", "commit"}:
        raise EvidenceValidationError("bundle.producer must contain name, version, and commit")
    if producer["name"] != "agent-control-verification":
        raise EvidenceValidationError("bundle.producer.name must be agent-control-verification")
    _require_nonempty_string(producer["version"], "bundle.producer.version")
    _require_optional_string(producer["commit"], "bundle.producer.commit")

    scenario = _require_mapping(root["scenario"], "bundle.scenario")
    if set(scenario) != {"id", "property"}:
        raise EvidenceValidationError("bundle.scenario must contain id and property")
    _require_nonempty_string(scenario["id"], "bundle.scenario.id")
    _require_nonempty_string(scenario["property"], "bundle.scenario.property")

    components = root["components"]
    if not isinstance(components, list):
        raise EvidenceValidationError("bundle.components must be an array")
    seen_roles: set[str] = set()
    for index, item in enumerate(components):
        component = _require_mapping(item, f"bundle.components[{index}]")
        if set(component) != {"role", "name", "version", "commit"}:
            raise EvidenceValidationError(
                f"bundle.components[{index}] must contain role, name, version, and commit"
            )
        role = _require_nonempty_string(component["role"], f"bundle.components[{index}].role")
        if role not in _COMPONENT_ROLES:
            raise EvidenceValidationError(f"bundle.components[{index}].role is unsupported")
        if role in seen_roles:
            raise EvidenceValidationError(f"bundle.components contains duplicate role: {role}")
        seen_roles.add(role)
        _require_nonempty_string(component["name"], f"bundle.components[{index}].name")
        _require_optional_string(component["version"], f"bundle.components[{index}].version")
        _require_optional_string(component["commit"], f"bundle.components[{index}].commit")

    action = _require_mapping(root["action"], "bundle.action")
    if set(action) != {"fingerprint"}:
        raise EvidenceValidationError("bundle.action must contain only fingerprint")
    _require_sha256(action["fingerprint"], "bundle.action.fingerprint")

    control = _require_mapping(root["control"], "bundle.control")
    if set(control) != {"decision", "reason_code", "reason_digest"}:
        raise EvidenceValidationError(
            "bundle.control must contain decision, reason_code, and reason_digest"
        )
    decision = _require_nonempty_string(control["decision"], "bundle.control.decision")
    if decision not in _CONTROL_DECISIONS:
        raise EvidenceValidationError("bundle.control.decision is unsupported")
    _require_optional_string(control["reason_code"], "bundle.control.reason_code")
    if control["reason_digest"] is not None:
        _require_sha256(control["reason_digest"], "bundle.control.reason_digest")

    evidence = _require_mapping(root["evidence"], "bundle.evidence")
    expected_evidence_keys = {
        "invocation_fingerprints",
        "effect_fingerprints",
        "audit_refs",
        "missing",
        "timeline",
    }
    if set(evidence) != expected_evidence_keys:
        raise EvidenceValidationError("bundle.evidence has an unexpected shape")
    for field in ("invocation_fingerprints", "effect_fingerprints"):
        fingerprints = _require_string_list(evidence[field], f"bundle.evidence.{field}")
        for index, fingerprint in enumerate(fingerprints):
            _require_sha256(fingerprint, f"bundle.evidence.{field}[{index}]")
    _require_string_list(evidence["audit_refs"], "bundle.evidence.audit_refs")
    missing = _require_string_list(evidence["missing"], "bundle.evidence.missing")
    if len(missing) != len(set(missing)):
        raise EvidenceValidationError("bundle.evidence.missing must not contain duplicates")

    timeline = evidence["timeline"]
    if not isinstance(timeline, list):
        raise EvidenceValidationError("bundle.evidence.timeline must be an array")
    sequences: list[int] = []
    for index, item in enumerate(timeline):
        event = _require_mapping(item, f"bundle.evidence.timeline[{index}]")
        if set(event) != {"sequence", "kind", "ref", "timestamp"}:
            raise EvidenceValidationError(
                f"bundle.evidence.timeline[{index}] has an unexpected shape"
            )
        sequence = event["sequence"]
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            raise EvidenceValidationError(
                f"bundle.evidence.timeline[{index}].sequence must be a non-negative integer"
            )
        sequences.append(sequence)
        kind = _require_nonempty_string(event["kind"], f"bundle.evidence.timeline[{index}].kind")
        if kind not in _EVENT_KINDS:
            raise EvidenceValidationError(f"bundle.evidence.timeline[{index}].kind is unsupported")
        _require_nonempty_string(event["ref"], f"bundle.evidence.timeline[{index}].ref")
        if event["timestamp"] is not None:
            _parse_time(event["timestamp"], f"bundle.evidence.timeline[{index}].timestamp")
    if sequences != list(range(len(sequences))):
        raise EvidenceValidationError("bundle.evidence.timeline sequences must be contiguous from zero")

    environment = _require_mapping(root["environment"], "bundle.environment")
    for key, value in environment.items():
        _require_nonempty_string(key, "bundle.environment key")
        _require_nonempty_string(value, f"bundle.environment.{key}")

    privacy = _require_mapping(root["privacy"], "bundle.privacy")
    if set(privacy) != {"raw_payloads_included", "redactions", "canary_ids"}:
        raise EvidenceValidationError("bundle.privacy has an unexpected shape")
    if privacy["raw_payloads_included"] is not False:
        raise EvidenceValidationError("bundle.privacy.raw_payloads_included must be false")
    _require_string_list(privacy["redactions"], "bundle.privacy.redactions")
    _require_string_list(privacy["canary_ids"], "bundle.privacy.canary_ids")

    result = _require_mapping(root["result"], "bundle.result")
    if set(result) != {"verdict", "reason"}:
        raise EvidenceValidationError("bundle.result must contain verdict and reason")
    verdict = _require_nonempty_string(result["verdict"], "bundle.result.verdict")
    if verdict not in _VERDICTS:
        raise EvidenceValidationError("bundle.result.verdict is unsupported")
    _require_nonempty_string(result["reason"], "bundle.result.reason")

    integrity = _require_mapping(root["integrity"], "bundle.integrity")
    if set(integrity) != {"algorithm", "digest"}:
        raise EvidenceValidationError("bundle.integrity must contain algorithm and digest")
    if integrity["algorithm"] != "sha256":
        raise EvidenceValidationError("bundle.integrity.algorithm must be sha256")
    supplied_digest = _require_sha256(integrity["digest"], "bundle.integrity.digest")
    expected_digest = compute_bundle_digest(root)
    if supplied_digest != expected_digest:
        raise EvidenceValidationError("bundle integrity digest does not match the bundle contents")


def build_evidence_bundle(
    *,
    bundle_id: str,
    created_at: datetime,
    acv_version: str,
    acv_commit: str | None,
    scenario_id: str,
    result: VerificationResult,
    action_fingerprint: str,
    control_decision: ControlDecision | str,
    control_reason_code: str | None = None,
    control_reason_digest: str | None = None,
    components: Sequence[ComponentVersion] = (),
    invocation_fingerprints: Iterable[str] = (),
    effect_fingerprints: Iterable[str] = (),
    audit_refs: Iterable[str] = (),
    missing_evidence: Iterable[str] = (),
    timeline: Sequence[EvidenceEvent] = (),
    environment: Mapping[str, str] | None = None,
    redactions: Iterable[str] = (),
    canary_ids: Iterable[str] = (),
) -> dict[str, Any]:
    decision_value = (
        control_decision.value if isinstance(control_decision, ControlDecision) else control_decision
    )
    bundle: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "bundle_id": bundle_id,
        "created_at": _format_time(created_at),
        "producer": {
            "name": "agent-control-verification",
            "version": acv_version,
            "commit": acv_commit,
        },
        "scenario": {
            "id": scenario_id,
            "property": result.property_name,
        },
        "components": [component.as_dict() for component in components],
        "action": {"fingerprint": action_fingerprint},
        "control": {
            "decision": decision_value,
            "reason_code": control_reason_code,
            "reason_digest": control_reason_digest,
        },
        "evidence": {
            "invocation_fingerprints": list(invocation_fingerprints),
            "effect_fingerprints": list(effect_fingerprints),
            "audit_refs": list(audit_refs),
            "missing": list(missing_evidence),
            "timeline": [event.as_dict() for event in timeline],
        },
        "environment": dict(environment or {}),
        "privacy": {
            "raw_payloads_included": False,
            "redactions": list(redactions),
            "canary_ids": list(canary_ids),
        },
        "result": {
            "verdict": result.verdict.value,
            "reason": result.reason,
        },
    }
    bundle["integrity"] = {
        "algorithm": "sha256",
        "digest": compute_bundle_digest(bundle),
    }
    validate_evidence_bundle(bundle)
    return bundle


def evidence_bundle_json(bundle: Mapping[str, Any], *, indent: int = 2) -> str:
    validate_evidence_bundle(bundle)
    return json.dumps(bundle, sort_keys=True, indent=indent, ensure_ascii=False) + "\n"


def load_evidence_bundle(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EvidenceValidationError("evidence bundle is not valid JSON") from exc
    bundle = dict(_require_mapping(value, "bundle"))
    validate_evidence_bundle(bundle)
    return bundle


def render_evidence_bundle(bundle: Mapping[str, Any]) -> str:
    validate_evidence_bundle(bundle)
    scenario = bundle["scenario"]
    control = bundle["control"]
    evidence = bundle["evidence"]
    result = bundle["result"]
    producer = bundle["producer"]
    missing = evidence["missing"]

    lines = [
        f"{result['verdict'].upper()} {scenario['property']}",
        f"Bundle: {bundle['bundle_id']}",
        f"Scenario: {scenario['id']}",
        f"ACV: {producer['version']}" + (f" ({producer['commit']})" if producer["commit"] else ""),
        f"Control decision: {control['decision']}",
        f"Action fingerprint: {bundle['action']['fingerprint']}",
        f"Invocation evidence: {len(evidence['invocation_fingerprints'])}",
        f"Effect evidence: {len(evidence['effect_fingerprints'])}",
        f"Audit references: {len(evidence['audit_refs'])}",
        "Missing evidence: " + (", ".join(missing) if missing else "none"),
        f"Reason: {result['reason']}",
        f"Integrity: sha256:{bundle['integrity']['digest']}",
    ]
    return "\n".join(lines)
