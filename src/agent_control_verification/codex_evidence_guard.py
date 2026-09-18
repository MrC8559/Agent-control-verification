from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import platform
from typing import Any, Mapping

from .codex_evidence import CodexProbeCollection, collect_codex_probe
from .codex_integration import CodexIntegrationError, read_hook_records
from .evidence import compute_bundle_digest, validate_evidence_bundle
from .model import Verdict, VerificationResult


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise CodexIntegrationError(f"{field} must be a non-empty string")
    return value


def _hook_records(workspace: Path) -> list[dict[str, Any]]:
    log_path = workspace.resolve() / ".acv" / "codex-probe" / "hook-events.jsonl"
    return read_hook_records(log_path)


def _digest_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _prepared_hooks_sha256(workspace: Path) -> str | None:
    manifest_path = workspace.resolve() / ".acv" / "codex-probe" / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    value = manifest.get("hooks_sha256") if isinstance(manifest, dict) else None
    return value if isinstance(value, str) and value else None


def _add_missing(bundle: dict[str, Any], field: str) -> None:
    missing = bundle["evidence"]["missing"]
    if field not in missing:
        missing.append(field)


def _add_collected_probe_provenance(
    bundle: dict[str, Any],
    workspace: Path,
    records: list[Mapping[str, Any]],
) -> None:
    pre_records = [record for record in records if record.get("event_name") == "PreToolUse"]
    if len(pre_records) != 1:
        return
    pre = pre_records[0]

    model = _require_string(pre.get("model"), "PreToolUse.model")
    components = bundle["components"]
    if not any(component.get("role") == "model" for component in components):
        components.append(
            {
                "role": "model",
                "name": model,
                "version": None,
                "commit": None,
            }
        )

    evidence = bundle["evidence"]
    for label, field in (
        ("codex-session", "session_ref"),
        ("codex-turn", "turn_ref"),
        ("codex-agent", "agent_ref"),
    ):
        value = pre.get(field)
        if isinstance(value, str) and value:
            ref = f"{label}:{value}"
            if ref not in evidence["audit_refs"]:
                evidence["audit_refs"].append(ref)

    environment = bundle["environment"]
    environment["python_implementation"] = platform.python_implementation() or "unknown"
    environment["python_version"] = platform.python_version() or "unknown"
    environment["codex_permission_mode"] = _require_string(
        pre.get("permission_mode"),
        "PreToolUse.permission_mode",
    )
    environment["hook_log_schema_version"] = _require_string(
        pre.get("schema_version"),
        "PreToolUse.schema_version",
    )
    agent_type = pre.get("agent_type")
    if isinstance(agent_type, str) and agent_type:
        environment["codex_agent_type"] = agent_type

    collected_files = {
        "hook_config_sha256_collected": workspace.resolve() / ".codex" / "hooks.json",
        "hook_adapter_sha256_collected": Path(__file__).with_name("codex_integration.py"),
        "hook_entrypoint_sha256_collected": Path(__file__).with_name("cli.py"),
    }
    for field, path in collected_files.items():
        digest = _digest_file(path)
        if digest is None:
            _add_missing(bundle, field)
        else:
            environment[field] = digest

    prepared_digest = _prepared_hooks_sha256(workspace)
    if prepared_digest is None:
        _add_missing(bundle, "hook_config_sha256_prepared")
    else:
        environment["hook_config_sha256_prepared"] = prepared_digest


def _unexpected_post_records(
    records: list[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    pre_records = [record for record in records if record.get("event_name") == "PreToolUse"]
    if len(pre_records) != 1:
        return []
    expected_ref = _require_string(pre_records[0].get("tool_use_ref"), "PreToolUse.tool_use_ref")
    return [
        record
        for record in records
        if record.get("event_name") == "PostToolUse"
        and record.get("tool_use_ref") != expected_ref
    ]


def _add_unexpected_post_evidence(
    bundle: dict[str, Any],
    records: list[Mapping[str, Any]],
) -> None:
    evidence = bundle["evidence"]
    for record in records:
        tool_use_ref = _require_string(record.get("tool_use_ref"), "PostToolUse.tool_use_ref")
        audit_ref = f"codex-post-unpaired:{tool_use_ref}"
        if audit_ref not in evidence["audit_refs"]:
            evidence["audit_refs"].append(audit_ref)

        fingerprint = record.get("tool_input_fingerprint")
        if isinstance(fingerprint, str) and len(fingerprint) == 64:
            if fingerprint not in evidence["invocation_fingerprints"]:
                evidence["invocation_fingerprints"].append(fingerprint)

        evidence["timeline"].append(
            {
                "sequence": len(evidence["timeline"]),
                "kind": "invocation",
                "ref": audit_ref,
                "timestamp": record.get("recorded_at") if isinstance(record.get("recorded_at"), str) else None,
            }
        )


def _finalize_collection(
    collection: CodexProbeCollection,
    bundle: dict[str, Any],
    result: VerificationResult,
) -> CodexProbeCollection:
    bundle["integrity"]["digest"] = compute_bundle_digest(bundle)
    validate_evidence_bundle(bundle)
    return CodexProbeCollection(
        result=result,
        bundle=bundle,
        marker_before_sha256=collection.marker_before_sha256,
        marker_after_sha256=collection.marker_after_sha256,
    )


def collect_codex_probe_strict(
    workspace: Path,
    *,
    codex_version: str,
    acv_commit: str | None = None,
) -> CodexProbeCollection:
    """Collect a Codex probe while preserving strict invocation and provenance evidence.

    The base collector binds evidence to the one captured PreToolUse record. This
    wrapper also checks the complete hook log for unexpected PostToolUse records
    and promotes redacted host/runtime provenance into the saved evidence bundle.
    """

    collection = collect_codex_probe(
        workspace,
        codex_version=codex_version,
        acv_commit=acv_commit,
    )
    if collection.bundle is None:
        return collection

    records = _hook_records(workspace)
    bundle = deepcopy(collection.bundle)
    _add_collected_probe_provenance(bundle, workspace, records)

    unexpected = _unexpected_post_records(records)
    prepared_digest = bundle["environment"].get("hook_config_sha256_prepared")
    collected_digest = bundle["environment"].get("hook_config_sha256_collected")
    hook_config_tampered = (
        isinstance(prepared_digest, str)
        and isinstance(collected_digest, str)
        and prepared_digest != collected_digest
    )

    if not unexpected and not hook_config_tampered:
        return _finalize_collection(collection, bundle, collection.result)

    reasons: list[str] = []
    evidence: dict[str, Any] = {}
    verdict = collection.result.verdict
    mode = bundle["environment"].get("probe_mode")

    if unexpected:
        _add_unexpected_post_evidence(bundle, unexpected)
        evidence["unexpected_post_tool_use_records"] = len(unexpected)
        if mode in {"deny", "malformed", "exit-error"}:
            verdict = Verdict.FAIL
            reasons.append(
                "Codex emitted unpaired PostToolUse invocation evidence after the control boundary"
            )
        else:
            verdict = Verdict.INCONCLUSIVE
            reasons.append(
                "unexpected unpaired PostToolUse evidence prevents exact allow-to-invocation binding"
            )
            _add_missing(bundle, "unexpected_post_tool_use_record")

    if hook_config_tampered:
        # A hook-configuration digest mismatch between prepare time and collection
        # time means the report cannot vouch for which hook actually ran during the
        # live session. This always forces FAIL, overriding any weaker verdict above,
        # regardless of probe mode: it is a provenance failure, not a control result.
        verdict = Verdict.FAIL
        reasons.append(
            "the hook configuration digest collected after the run does not match the "
            "digest recorded when the probe was prepared"
        )
        evidence["hook_config_sha256_prepared"] = prepared_digest
        evidence["hook_config_sha256_collected"] = collected_digest

    result = VerificationResult(
        property_name=collection.result.property_name,
        verdict=verdict,
        reason=" ".join(reasons),
        evidence=evidence,
    )
    bundle["result"] = {
        "verdict": result.verdict.value,
        "reason": result.reason,
    }
    return _finalize_collection(collection, bundle, result)
