from __future__ import annotations

from .model import Action, Observation
from .sandbox import SyntheticSandbox
from .targets import Target


def observe_run(target: Target, action: Action, sandbox: SyntheticSandbox | None = None) -> Observation:
    lab = sandbox or SyntheticSandbox()
    effect_start = len(lab.effects)
    audit_start = len(lab.audit_events)

    decision = target.run(action, lab)

    return Observation(
        requested_action=action,
        decision=decision,
        effects=tuple(lab.effects[effect_start:]),
        audit_events=tuple(lab.audit_events[audit_start:]),
    )
