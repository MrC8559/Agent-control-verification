from __future__ import annotations

from dataclasses import dataclass

from .model import Action, VerificationResult
from .observer import observe_run
from .targets import (
    DenyButExecutesTarget,
    HardenedDemoTarget,
    MissingAuditTarget,
    MutateAfterAllowTarget,
)
from .verifier import (
    verify_allow_binds_exact_action,
    verify_consequential_effect_is_audited,
    verify_deny_prevents_effect,
)


@dataclass(frozen=True)
class DemoCase:
    name: str
    result: VerificationResult


def run_demo() -> list[DemoCase]:
    protected = Action(
        action_id="demo-deny",
        tool="file.write",
        target="/protected/config.txt",
        arguments={"content": "should never be written"},
    )
    ordinary = Action(
        action_id="demo-allow",
        tool="file.write",
        target="/tmp/output.txt",
        arguments={"content": "approved"},
    )
    audit_action = Action(
        action_id="demo-audit",
        tool="email.send",
        target="synthetic@example.invalid",
        arguments={"subject": "synthetic", "body": "local only"},
    )

    return [
        DemoCase(
            "hardened-deny",
            verify_deny_prevents_effect(observe_run(HardenedDemoTarget(), protected)),
        ),
        DemoCase(
            "deny-but-executes",
            verify_deny_prevents_effect(observe_run(DenyButExecutesTarget(), protected)),
        ),
        DemoCase(
            "mutate-after-allow",
            verify_allow_binds_exact_action(observe_run(MutateAfterAllowTarget(), ordinary)),
        ),
        DemoCase(
            "missing-audit",
            verify_consequential_effect_is_audited(observe_run(MissingAuditTarget(), audit_action)),
        ),
    ]
