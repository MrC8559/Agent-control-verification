"""Agent Control Verification."""

from .approval import (
    ApprovalAttempt,
    ApprovalGrant,
    approval_binding_fingerprint,
    make_approval_grant,
    verify_approval_exact_binding,
    verify_approval_freshness,
    verify_single_use_approval,
)
from .failure import (
    ControlCause,
    ControlFailureObservation,
    FailurePosture,
    SyntheticHostBehavior,
    simulate_control_failure,
    verify_control_failure_does_not_silently_execute,
)
from .model import (
    Action,
    AuditEvent,
    ControlDecision,
    DecisionRecord,
    EffectRecord,
    Observation,
    Verdict,
    VerificationResult,
)
from .verifier import (
    verify_allow_binds_exact_action,
    verify_consequential_effect_is_audited,
    verify_deny_prevents_effect,
)

__all__ = [
    "Action",
    "ApprovalAttempt",
    "ApprovalGrant",
    "AuditEvent",
    "ControlCause",
    "ControlDecision",
    "ControlFailureObservation",
    "DecisionRecord",
    "EffectRecord",
    "FailurePosture",
    "Observation",
    "SyntheticHostBehavior",
    "Verdict",
    "VerificationResult",
    "approval_binding_fingerprint",
    "make_approval_grant",
    "simulate_control_failure",
    "verify_allow_binds_exact_action",
    "verify_approval_exact_binding",
    "verify_approval_freshness",
    "verify_consequential_effect_is_audited",
    "verify_control_failure_does_not_silently_execute",
    "verify_deny_prevents_effect",
    "verify_single_use_approval",
]

__version__ = "0.0.1"
