from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import platform
from pathlib import Path
import re
from typing import Any

from .codex_evidence import detect_codex_version
from .codex_integration import (
    CODEX_TARGET_VERSION,
    PROBE_SCHEMA_VERSION,
    SUPPORTED_PRE_MODES,
    CodexIntegrationError,
)
from .evidence import sha256_text


_ACV_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")


@dataclass(frozen=True)
class PreflightCheck:
    name: str
    passed: bool
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": "pass" if self.passed else "fail",
            "detail": self.detail,
        }


@dataclass(frozen=True)
class CodexPreflightReport:
    checks: tuple[PreflightCheck, ...]
    workspace: str | None
    os: str
    architecture: str
    python_version: str

    @property
    def ready(self) -> bool:
        return all(check.passed for check in self.checks)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "workspace": self.workspace,
            "os": self.os,
            "architecture": self.architecture,
            "python_version": self.python_version,
            "checks": [check.as_dict() for check in self.checks],
        }


def _check(name: str, passed: bool, detail: str) -> PreflightCheck:
    return PreflightCheck(name=name, passed=passed, detail=detail)


def _read_json_object(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _safe_relative_path(value: Any) -> Path | None:
    if not isinstance(value, str) or not value:
        return None
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        return None
    return path


def _workspace_checks(workspace: Path) -> list[PreflightCheck]:
    checks: list[PreflightCheck] = []
    workspace = workspace.resolve()
    workspace_ok = workspace.exists() and workspace.is_dir()

    checks.append(
        _check(
            "workspace_directory",
            workspace_ok,
            f"workspace exists as a directory: {workspace}"
            if workspace_ok
            else f"workspace is missing or is not a directory: {workspace}",
        )
    )
    if not workspace_ok:
        return checks

    manifest_path = workspace / ".acv" / "codex-probe" / "manifest.json"
    manifest = _read_json_object(manifest_path)
    checks.append(
        _check(
            "probe_manifest",
            manifest is not None,
            f"readable probe manifest: {manifest_path}"
            if manifest is not None
            else f"probe manifest is missing or invalid: {manifest_path}",
        )
    )
    if manifest is None:
        return checks

    checks.append(
        _check(
            "probe_schema",
            manifest.get("schema_version") == PROBE_SCHEMA_VERSION,
            f"manifest schema is {manifest.get('schema_version')!r}; expected {PROBE_SCHEMA_VERSION!r}",
        )
    )

    expected_host = manifest.get("codex_expected_version")
    checks.append(
        _check(
            "manifest_host_pin",
            expected_host == CODEX_TARGET_VERSION,
            f"manifest host pin is {expected_host!r}; expected {CODEX_TARGET_VERSION!r}",
        )
    )

    mode = manifest.get("pre_mode")
    mode_ok = isinstance(mode, str) and mode in SUPPORTED_PRE_MODES
    checks.append(_check("probe_mode", mode_ok, f"probe mode is {mode!r}"))

    marker_rel = _safe_relative_path(manifest.get("marker_path"))
    marker_path = (workspace / marker_rel).resolve() if marker_rel is not None else None
    marker_inside = marker_path is not None and marker_path.is_relative_to(workspace)
    checks.append(
        _check(
            "marker_path",
            marker_inside,
            f"marker path resolves inside workspace: {marker_path if marker_path else 'invalid'}",
        )
    )

    if marker_inside and marker_path is not None:
        try:
            marker_bytes = marker_path.read_bytes()
        except OSError:
            marker_bytes = None
        manifest_before = manifest.get("marker_before_sha256")
        expected_baseline = sha256_text("BASELINE\n")
        marker_digest = hashlib.sha256(marker_bytes).hexdigest() if marker_bytes is not None else None
        marker_ok = (
            marker_digest is not None
            and manifest_before == expected_baseline
            and marker_digest == manifest_before
        )
        checks.append(
            _check(
                "marker_baseline",
                marker_ok,
                "marker matches the recorded BASELINE state"
                if marker_ok
                else "marker is missing, changed, or disagrees with the recorded baseline digest",
            )
        )

    hooks_rel = _safe_relative_path(manifest.get("hooks_path"))
    hooks_path = (workspace / hooks_rel).resolve() if hooks_rel is not None else None
    hooks_inside = hooks_path is not None and hooks_path.is_relative_to(workspace)
    hooks = _read_json_object(hooks_path) if hooks_inside and hooks_path is not None else None
    checks.append(
        _check(
            "hook_config",
            hooks is not None,
            f"readable project hook config: {hooks_path if hooks_path else 'invalid'}"
            if hooks is not None
            else f"project hook config is missing or invalid: {hooks_path if hooks_path else 'invalid'}",
        )
    )

    if hooks is not None and mode_ok:
        try:
            pre_entry = hooks["hooks"]["PreToolUse"][0]
            post_entry = hooks["hooks"]["PostToolUse"][0]
            pre_hook = pre_entry["hooks"][0]
            post_hook = post_entry["hooks"][0]
            hook_shape_ok = (
                pre_entry.get("matcher") == "^apply_patch$"
                and post_entry.get("matcher") == "^apply_patch$"
                and pre_hook.get("type") == "command"
                and post_hook.get("type") == "command"
                and "codex-hook" in pre_hook.get("command", "")
                and f"--mode {mode}" in pre_hook.get("command", "")
                and "codex-hook" in post_hook.get("command", "")
                and "--mode observe" in post_hook.get("command", "")
            )
        except (KeyError, IndexError, TypeError, AttributeError):
            hook_shape_ok = False
        checks.append(
            _check(
                "hook_scope",
                hook_shape_ok,
                "PreToolUse/PostToolUse remain limited to apply_patch and the selected fixture mode"
                if hook_shape_ok
                else "hook configuration does not match the narrow apply_patch probe contract",
            )
        )

    log_rel = _safe_relative_path(manifest.get("hook_log_path"))
    log_path = (workspace / log_rel).resolve() if log_rel is not None else None
    log_inside = log_path is not None and log_path.is_relative_to(workspace)
    log_unused = log_inside and log_path is not None and not log_path.exists()
    checks.append(
        _check(
            "unused_hook_log",
            log_unused,
            "no hook events have been recorded in this workspace yet"
            if log_unused
            else "hook log already exists or its path is invalid; use a fresh workspace for publishable evidence",
        )
    )

    evidence_path = workspace / ".acv" / "codex-probe" / "evidence.json"
    evidence_unused = not evidence_path.exists()
    checks.append(
        _check(
            "unused_evidence_path",
            evidence_unused,
            "no prior evidence bundle exists in this workspace"
            if evidence_unused
            else "an evidence bundle already exists; use a fresh workspace for a new live run",
        )
    )
    return checks


def sys_version_info_at_least_311() -> bool:
    import sys

    return sys.version_info >= (3, 11)


def run_codex_preflight(
    workspace: Path | None = None,
    *,
    codex_executable: str = "codex",
    acv_commit: str | None,
) -> CodexPreflightReport:
    checks: list[PreflightCheck] = []

    try:
        observed_version = detect_codex_version(codex_executable)
    except CodexIntegrationError as exc:
        checks.append(_check("codex_host", False, str(exc)))
    else:
        checks.append(
            _check(
                "codex_host",
                observed_version == CODEX_TARGET_VERSION,
                f"observed Codex {observed_version}; pinned target is {CODEX_TARGET_VERSION}",
            )
        )

    checks.append(
        _check(
            "python_runtime",
            sys_version_info_at_least_311(),
            f"Python {platform.python_version()} ({platform.python_implementation()})",
        )
    )

    commit_ok = isinstance(acv_commit, str) and _ACV_COMMIT_RE.fullmatch(acv_commit) is not None
    checks.append(
        _check(
            "acv_commit",
            commit_ok,
            f"ACV commit: {acv_commit}"
            if commit_ok
            else "ACV commit is missing or is not a full hexadecimal commit identifier",
        )
    )

    if workspace is not None:
        checks.extend(_workspace_checks(workspace))

    return CodexPreflightReport(
        checks=tuple(checks),
        workspace=str(workspace.resolve()) if workspace is not None else None,
        os=platform.system() or "unknown",
        architecture=platform.machine() or "unknown",
        python_version=platform.python_version() or "unknown",
    )


def render_codex_preflight(report: CodexPreflightReport) -> str:
    heading = "READY" if report.ready else "NOT READY"
    lines = [f"{heading} Codex {CODEX_TARGET_VERSION} live-probe preflight"]
    for check in report.checks:
        status = "PASS" if check.passed else "FAIL"
        lines.append(f"{status:4} {check.name}: {check.detail}")
    lines.append(f"Environment: {report.os} {report.architecture}, Python {report.python_version}")
    if report.workspace:
        lines.append(f"Workspace: {report.workspace}")
    if report.ready:
        lines.append("Preflight only establishes readiness to run the narrow probe; it is not host evidence.")
    return "\n".join(lines)
