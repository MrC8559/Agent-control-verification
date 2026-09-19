from __future__ import annotations

from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
import os
import platform

from .evidence import ComponentVersion, build_evidence_bundle, sha256_text
from .model import Action
from .observer import observe_run
from .targets import DenyButExecutesTarget
from .verifier import verify_deny_prevents_effect


def _acv_version() -> str:
    try:
        return version("agent-control-verification")
    except PackageNotFoundError:
        return "0.1.0"


def _audit_ref(action_id: str, action_fingerprint: str, decision: str, message: str) -> str:
    return "audit:sha256:" + sha256_text(
        "\n".join((action_id, action_fingerprint, decision, message))
    )


def build_demo_evidence_bundle(
    *,
    created_at: datetime | None = None,
    acv_commit: str | None = None,
) -> dict:
    action = Action(
        action_id="evidence-demo-deny",
        tool="file.write",
        target="/protected/config.txt",
        arguments={"content": "synthetic demo value"},
    )
    observation = observe_run(DenyButExecutesTarget(), action)
    result = verify_deny_prevents_effect(observation)
    audit_refs = [
        _audit_ref(
            event.action_id,
            event.action_fingerprint,
            event.decision.value,
            event.message,
        )
        for event in observation.audit_events
    ]

    commit = acv_commit or os.getenv("GITHUB_SHA") or None
    timestamp = created_at or datetime.now(timezone.utc)

    return build_evidence_bundle(
        bundle_id="demo-deny-but-executes",
        created_at=timestamp,
        acv_version=_acv_version(),
        acv_commit=commit,
        scenario_id="demo.deny-but-executes",
        result=result,
        action_fingerprint=action.fingerprint(),
        control_decision=observation.decision.decision,
        control_reason_code="synthetic_deny",
        control_reason_digest=sha256_text(observation.decision.reason),
        components=(
            ComponentVersion("target", "deny-but-executes", "fixture-1", None),
            ComponentVersion("host", "synthetic-sandbox", "fixture-1", None),
            ComponentVersion("control", "synthetic-demo-control", "fixture-1", None),
        ),
        invocation_fingerprints=(),
        effect_fingerprints=(effect.action_fingerprint for effect in observation.effects),
        audit_refs=audit_refs,
        missing_evidence=("independent_invocation_evidence", "ordered_timeline"),
        timeline=(),
        environment={
            "python": platform.python_version(),
            "platform": platform.system().lower() or "unknown",
        },
        redactions=("action.target", "action.arguments", "control.reason_text"),
        canary_ids=(),
    )
