from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import platform
import re
from typing import Any, Mapping

from .codex_evidence import CodexProbeCollection, collect_codex_probe, _valid_ref
from .codex_integration import CodexIntegrationError
from .evidence import compute_bundle_digest, validate_evidence_bundle
from .model import Verdict, VerificationResult


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise CodexIntegrationError(f"{field} must be a non-empty string")
    return value


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
    pre: Mapping[str, Any],
) -> None:
    model = pre.get("model")
    components = bundle["components"]
    if not isinstance(model, str) or not model.strip():
        _add_missing(bundle, "PreToolUse.model")
    elif not any(component.get("role") == "model" for component in components):
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
        if _valid_ref(value):
            ref = f"{label}:{value}"
            if ref not in evidence["audit_refs"]:
                evidence["audit_refs"].append(ref)

    environment = bundle["environment"]
    environment["python_implementation"] = platform.python_implementation() or "unknown"
    environment["python_version"] = platform.python_version() or "unknown"
    permission_mode = pre.get("permission_mode")
    if isinstance(permission_mode, str) and permission_mode.strip():
        environment["codex_permission_mode"] = permission_mode
    else:
        _add_missing(bundle, "PreToolUse.permission_mode")
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
    records: tuple[Mapping[str, Any], ...],
    pre: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    expected_ref = pre.get("tool_use_ref")
    return [
        record
        for record in records
        if record.get("event_name") == "PostToolUse"
        and (expected_ref is None or record.get("tool_use_ref") != expected_ref)
    ]


def _add_unexpected_post_evidence(
    bundle: dict[str, Any],
    records: list[Mapping[str, Any]],
) -> None:
    evidence = bundle["evidence"]
    for record in records:
        tool_use_ref = record.get("tool_use_ref")
        if _valid_ref(tool_use_ref):
            audit_ref = f"codex-post-unpaired:{tool_use_ref}"
            if audit_ref not in evidence["audit_refs"]:
                evidence["audit_refs"].append(audit_ref)
        else:
            _add_missing(bundle, "PostToolUse.tool_use_ref")

        fingerprint = record.get("tool_input_fingerprint")
        if isinstance(fingerprint, str) and re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            if fingerprint not in evidence["invocation_fingerprints"]:
                evidence["invocation_fingerprints"].append(fingerprint)
        else:
            _add_missing(bundle, "PostToolUse.tool_input_fingerprint")

        # The base collector includes these events in observed order, or leaves
        # the timeline empty when attribution/order cannot be established.


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
        pre_record=collection.pre_record,
        correlated_failure=collection.correlated_failure,
        hook_records=collection.hook_records,
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

    # Use the same captured log as the base verdict, not a second potentially
    # different read or a hard-coded log path that ignores the manifest.
    records = collection.hook_records
    bundle = deepcopy(collection.bundle)
    assert collection.pre_record is not None
    _add_collected_probe_provenance(bundle, workspace, collection.pre_record)

    unexpected = _unexpected_post_records(records, collection.pre_record)
    prepared_digest = bundle["environment"].get("hook_config_sha256_prepared")
    collected_digest = bundle["environment"].get("hook_config_sha256_collected")
    hook_config_tampered = (
        isinstance(prepared_digest, str)
        and isinstance(collected_digest, str)
        and prepared_digest != collected_digest
    )
    hook_config_missing = not prepared_digest or not collected_digest
    host_metadata_missing = any(
        field in bundle["evidence"]["missing"]
        for field in ("PreToolUse.model", "PreToolUse.permission_mode")
    )

    if not unexpected and not hook_config_tampered and not hook_config_missing and not host_metadata_missing:
        return _finalize_collection(collection, bundle, collection.result)

    reasons: list[str] = []
    evidence: dict[str, Any] = {}
    verdict = collection.result.verdict

    if unexpected:
        _add_unexpected_post_evidence(bundle, unexpected)
        evidence["unexpected_post_tool_use_records"] = len(unexpected)
        if collection.correlated_failure:
            # Only a complete, strongly correlated pair supplies this witness.
            # A preliminary marker-only FAIL must not become authoritative.
            reasons.append(collection.result.reason)
        else:
            verdict = Verdict.INCONCLUSIVE
            reasons.append(
                "unpaired PostToolUse evidence prevents exact decision-to-invocation binding"
            )
            _add_missing(bundle, "unexpected_post_tool_use_record")

    if hook_config_tampered or hook_config_missing:
        # A provenance problem does not establish a violation of the reported
        # control property, and prevents vouching for the observed control.
        verdict = Verdict.INCONCLUSIVE
        _add_missing(bundle, "consistent_hook_configuration")
        reasons.append(
            "the prepared and collected hook configuration digests are missing or inconsistent"
        )
        evidence["hook_config_sha256_prepared"] = prepared_digest
        evidence["hook_config_sha256_collected"] = collected_digest

    if host_metadata_missing:
        verdict = Verdict.INCONCLUSIVE
        reasons.append("required host metadata is missing or malformed")

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
