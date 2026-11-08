"""
BaitBox — M3 Policy and Approval Gate (backend/app/policy_gate.py)
==================================================================
A deterministic, purely rule-based security gate between every decision the
planning model makes (M2) and every action the disposable chamber (M5) performs.

Why rule-based? Because a model can be talked out of a decision by prompt
injection hidden inside a hostile page; a deterministic rule engine cannot.

Core rules:
1. Fixed Action Allow-List: Only `load`, `wait`, `scroll`, `click_verify`,
   `fill_decoy`, and `stop` are permitted. Any action invented by the model
   (e.g. `submit_form`, `type_password`, `open_internal`, `exec_shell`) is
   immediately BLOCKED.
2. Step Budget Enforcement: Hard ceiling of 8 actions per scan.
3. Egress & SSRF Check on Action Targets: Any `load` action targeting
   `169.254.169.254`, private RFC1918 IPs, or the control plane is BLOCKED.
4. Decoy Identity Hygiene: Typing into fields is blocked unless the action is
   `fill_decoy` and every credential value comes strictly from `DECOY_IDENTITY`.
   Submitting a credential form is ALWAYS blocked unless human approval is
   explicitly granted with decoy-only values.
5. Objective 5 (Human Approval Gate): When `require_human_approval` is enabled
   and the agent proposes `click_verify` or `fill_decoy`, M3 returns `ask` so
   the user must approve the single action in the Web Console.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Set

from .egress_rules import check_outbound_url_allowed
from .schemas import ContainmentEvent, GateCheckResult, ProposedAction

ALLOWED_ACTIONS: Set[str] = {
    "load",
    "wait",
    "scroll",
    "click_verify",
    "fill_decoy",
    "stop",
}

FORBIDDEN_ACTIONS: Set[str] = {
    "submit_form",
    "submit",
    "type_real_credentials",
    "fetch_metadata",
    "exec_code",
    "shell",
    "download_and_execute",
    "exfiltrate",
}

DECOY_IDENTITY: Dict[str, str] = {
    "full_name": "Alex Rivera (BaitBox Decoy Canary)",
    "username": "alex.rivera.decoy00",
    "email": "decoy-canary-000@baitbox.invalid",
    "password": "DecoyCanary!NotARealPassword99",
    "phone": "+60-10-000-0000",
    "account_number": "0000-0000-0000-DECOY",
    "otp_code": "000000",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PolicyAndApprovalGate:
    """M3: Deterministic rule check between M2 (Orchestrator) and M5 (Detonation Worker)."""

    def __init__(self, max_steps: int = 8) -> None:
        self.max_steps = max_steps

    def check_action(
        self,
        proposed: ProposedAction,
        step_index: int,
        require_human_approval: bool = False,
        already_approved_this_step: bool = False,
    ) -> GateCheckResult:
        action = (proposed.action or "").strip().lower()
        target = (proposed.target or "").strip()

        # 1. Step budget check
        if step_index > self.max_steps and action != "stop":
            evt = ContainmentEvent(
                timestamp=_now_iso(),
                module="M3 Policy Gate",
                category="policy_gate_block",
                severity="warning",
                title=f"Step budget exhausted ({self.max_steps} steps max)",
                detail=f"Blocked action '{action}' at step {step_index}; forcing 'stop'.",
                metadata={"step_index": step_index, "proposed_action": action},
            )
            return GateCheckResult(
                decision="block",
                action="stop",
                reason=evt.detail,
                containment_event=evt,
            )

        # 2. Explicitly forbidden / prompt-injected actions (e.g., submit_form)
        if action in FORBIDDEN_ACTIONS or action not in ALLOWED_ACTIONS:
            evt = ContainmentEvent(
                timestamp=_now_iso(),
                module="M3 Policy Gate",
                category="policy_gate_block",
                severity="critical",
                title=f"Refused disallowed agent action: '{action}'",
                detail=(
                    f"M3 Policy Gate refused proposed action '{action}' (target='{target}'). "
                    f"Only fixed allow-list actions {sorted(ALLOWED_ACTIONS)} are permitted; "
                    f"form submissions and unapproved commands are strictly prohibited."
                ),
                metadata={
                    "proposed_action": action,
                    "target": target,
                    "source": proposed.source,
                },
            )
            return GateCheckResult(
                decision="block",
                action=action,
                reason=evt.detail,
                containment_event=evt,
            )

        # 3. Validate URL targets on `load` actions against SSRF / metadata rules
        if action == "load":
            allowed, egress_reason = check_outbound_url_allowed(target)
            if not allowed:
                evt = ContainmentEvent(
                    timestamp=_now_iso(),
                    module="M3 Policy Gate",
                    category="policy_gate_block",
                    severity="critical",
                    title=f"Blocked navigation to restricted address: {target}",
                    detail=f"M3 Policy Gate blocked '{action}' to '{target}': {egress_reason}",
                    metadata={"proposed_action": action, "target": target},
                )
                return GateCheckResult(
                    decision="block",
                    action=action,
                    reason=evt.detail,
                    containment_event=evt,
                )

        # 4. Validate `fill_decoy` uses ONLY decoy identity values
        if action == "fill_decoy":
            supplied_values = proposed.parameters.get("values", {})
            if supplied_values:
                allowed_vals = set(DECOY_IDENTITY.values())
                for k, v in supplied_values.items():
                    if str(v) not in allowed_vals:
                        evt = ContainmentEvent(
                            timestamp=_now_iso(),
                            module="M3 Policy Gate",
                            category="policy_gate_block",
                            severity="critical",
                            title=f"Blocked non-decoy field input for '{k}'",
                            detail=(
                                "M3 Policy Gate blocked typing non-decoy data into a form field. "
                                "Only synthetic canary values from DECOY_IDENTITY are permitted."
                            ),
                            metadata={"field": k},
                        )
                        return GateCheckResult(
                            decision="block",
                            action=action,
                            reason=evt.detail,
                            containment_event=evt,
                        )
            # Enforce decoy dictionary overwrite
            proposed.parameters["decoy_identity"] = dict(DECOY_IDENTITY)

        # 5. Objective 5: Human Approval Gate for interactive clicks or decoy form fills
        if (
            action in ("click_verify", "fill_decoy")
            and require_human_approval
            and not already_approved_this_step
        ):
            evt = ContainmentEvent(
                timestamp=_now_iso(),
                module="M3 Policy Gate",
                category="policy_gate_ask",
                severity="warning",
                title=f"Paused for human approval: '{action}'",
                detail=(
                    f"Page requires interactive step ('{action}' on '{target or 'button/form'}'). "
                    "M3 Policy Gate paused execution to request explicit human approval "
                    "(using decoy canary data only)."
                ),
                metadata={
                    "step_index": step_index,
                    "proposed_action": action,
                    "target": target,
                    "decoy_identity": DECOY_IDENTITY,
                },
            )
            return GateCheckResult(
                decision="ask",
                action=action,
                reason=evt.detail,
                containment_event=evt,
            )

        # 6. Action allowed
        category = "decoy_credentials_used" if action == "fill_decoy" else "policy_gate_allow"
        title = (
            "Populated form fields with synthetic Decoy Canary identity (never submitted)"
            if action == "fill_decoy"
            else f"Allowed safe chamber action: '{action}'"
        )
        evt = ContainmentEvent(
            timestamp=_now_iso(),
            module="M3 Policy Gate",
            category=category,
            severity="info",
            title=title,
            detail=(
                f"Step {step_index}/{self.max_steps}: M3 Policy Gate verified '{action}' "
                f"against fixed allow-list ({proposed.reason or 'standard inspection step'})."
            ),
            metadata={"step_index": step_index, "action": action, "target": target},
        )
        return GateCheckResult(
            decision="allow",
            action=action,
            reason=evt.detail,
            containment_event=evt,
        )
