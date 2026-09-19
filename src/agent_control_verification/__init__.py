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
from .evidence import (
    ComponentVersion,
    EvidenceEvent,
    EvidenceValidationError,
    build_evidence_bundle,
    compute_bundle_digest,
    evidence_bundle_json,
    load_evidence_bundle,
    render_evidence_bundle,
    sha256_text,
    validate_evidence_bundle,
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
    "ComponentVersion",
    "ControlCause",
    "ControlDecision",
    "ControlFailureObservation",
    "DecisionRecord",
    "EffectRecord",
    "EvidenceEvent",
    "EvidenceValidationError",
    "FailurePosture",
    "Observation",
    "SyntheticHostBehavior",
    "Verdict",
    "VerificationResult",
    "approval_binding_fingerprint",
    "build_evidence_bundle",
    "compute_bundle_digest",
    "evidence_bundle_json",
    "load_evidence_bundle",
    "make_approval_grant",
    "render_evidence_bundle",
    "sha256_text",
    "simulate_control_failure",
    "validate_evidence_bundle",
    "verify_allow_binds_exact_action",
    "verify_approval_exact_binding",
    "verify_approval_freshness",
    "verify_consequential_effect_is_audited",
    "verify_control_failure_does_not_silently_execute",
    "verify_deny_prevents_effect",
    "verify_single_use_approval",
]

__version__ = "0.1.0"
