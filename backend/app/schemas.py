"""
BaitBox — Data Schemas & Boundary Contracts (backend/app/schemas.py)
====================================================================
Defines strict data structures across all 8 BaitBox modules:
- Only fixed-format `EvidenceBundle` data crosses from M5 (Detonation Worker)
  into M2 (Orchestrator) and M7 (Analyst).
- Never commands or executable instructions.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


VerdictType = Literal["Likely safe", "Suspicious", "Dangerous"]
ScanStatusType = Literal[
    "queued",
    "running",
    "waiting_approval",
    "completed",
    "timed_out",
    "failed",
]
AllowedActionType = Literal[
    "load",
    "wait",
    "scroll",
    "click_verify",
    "fill_decoy",
    "stop",
]
GateDecisionType = Literal["allow", "block", "ask"]


class ScanCreateRequest(BaseModel):
    input_text: str = Field(
        ...,
        description="URL or pasted message text containing a suspicious link.",
        min_length=3,
    )
    require_human_approval: bool = Field(
        default=False,
        description="Objective 5: Pause and ask user approval before clicking interactive verification buttons or filling decoy data.",
    )
    simulate_timeout: bool = Field(
        default=False,
        description="Used by containment tests to force wall-clock expiry and verify chamber destruction.",
    )


class ApprovalRequest(BaseModel):
    decision: Literal["approve", "deny"] = Field(
        ..., description="User decision for pending interactive action."
    )


class HopRecord(BaseModel):
    hop_index: int
    url: str
    domain: str
    status_code: int
    latency_ms: int
    screenshot_url: Optional[str] = None
    note: str = ""


class FormInputField(BaseModel):
    name: str = ""
    type: str = "text"
    placeholder: str = ""
    required: bool = False


class FormRecord(BaseModel):
    form_index: int
    action: str = ""
    method: str = "GET"
    inputs: List[FormInputField] = Field(default_factory=list)
    has_password: bool = False
    has_card_or_otp: bool = False


class QuarantinedDownload(BaseModel):
    filename: str
    url: str
    content_type: str = "application/octet-stream"
    size_bytes: int = 0
    sha256: str
    is_eicar: bool = False
    quarantined_by: str = "M6 Egress Filter"
    reason: str = ""


class ContainmentEvent(BaseModel):
    timestamp: str
    module: Literal["M3 Policy Gate", "M4 Chamber Manager", "M5 Detonation Worker", "M6 Egress Filter", "M7 Analyst"]
    category: Literal[
        "chamber_started",
        "chamber_hardened",
        "egress_blocked",
        "download_quarantined",
        "prompt_injection_neutralized",
        "policy_gate_allow",
        "policy_gate_block",
        "policy_gate_ask",
        "decoy_credentials_used",
        "chamber_timed_out",
        "chamber_destroyed",
    ]
    severity: Literal["info", "warning", "critical"] = "info"
    title: str
    detail: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EvidenceBundle(BaseModel):
    """
    The ONLY structure allowed to cross from the disposable detonation chamber
    (M5/M6) into the trusted control plane (M2/M7). Treated strictly as
    untrusted data, never as instructions.
    """

    scan_id: str
    step_index: int
    action_performed: str
    initial_url: str
    final_url: str
    page_title: str = ""
    hops: List[HopRecord] = Field(default_factory=list)
    visible_text: str = ""
    hidden_texts: List[str] = Field(default_factory=list)
    forms: List[FormRecord] = Field(default_factory=list)
    external_scripts: List[str] = Field(default_factory=list)
    network_attempts: List[Dict[str, Any]] = Field(default_factory=list)
    downloads_quarantined: List[QuarantinedDownload] = Field(default_factory=list)
    egress_blocks: List[Dict[str, Any]] = Field(default_factory=list)
    final_screenshot_url: Optional[str] = None
    final_screenshot_path: Optional[str] = None
    requires_interaction_button: Optional[str] = None


class ProposedAction(BaseModel):
    action: str
    target: str = ""
    reason: str = ""
    parameters: Dict[str, Any] = Field(default_factory=dict)
    source: str = "vultr_planner"


class GateCheckResult(BaseModel):
    decision: GateDecisionType
    action: str
    reason: str
    containment_event: ContainmentEvent


class RuleSignal(BaseModel):
    code: str
    severity: Literal["low", "medium", "high", "critical"]
    description: str
    score_delta: int


class AnalystResult(BaseModel):
    verdict: VerdictType
    reason: str = Field(
        ...,
        description="Two-sentence plain-language explanation suitable for a non-expert.",
    )
    impersonated_brand: Optional[str] = None
    risk_score: int = Field(default=0, ge=0, le=100)
    rule_signals: List[RuleSignal] = Field(default_factory=list)
    agent_injection_findings: List[str] = Field(default_factory=list)
    model_used: str = ""
    inference_provider: str = "Vultr Serverless Inference (api.vultrinference.com/v1)"
    caveat: str = (
        "BaitBox's verdict is advice, not a guarantee. A 'Likely safe' result means "
        "nothing harmful was seen during one visit, not that the site is trustworthy."
    )


class ChamberLifecycleReceipt(BaseModel):
    chamber_id: str
    backend_mode: str
    runtime: str
    image: str
    user: str = "10001:10001 (non-root)"
    rootfs: str = "read-only + tmpfs (/tmp noexec,nosuid,nodev)"
    capabilities: str = "cap_drop=ALL, no-new-privileges=true"
    cpu_limit: str = "1.0 vCPU"
    memory_limit: str = "1024 MB"
    pids_limit: int = 256
    wall_clock_limit_seconds: int = 90
    network_mode: str = "isolated internal bridge -> M6 mitmproxy egress filter only"
    secrets_injected: int = 0
    started_at: str
    destroyed_at: str
    lifetime_seconds: float
    destroyed_cleanly: bool = True
    termination_reason: str = "scan_completed"


class PendingApprovalPrompt(BaseModel):
    step_index: int
    proposed_action: str
    button_label: str
    explanation: str
    decoy_preview: Dict[str, str]


class ScanReport(BaseModel):
    scan_id: str
    share_token: str
    status: ScanStatusType
    submitted_input: str
    normalized_url: str
    masked_url: str
    final_url: str = ""
    page_title: str = ""
    created_at: str
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0
    verdict: Optional[VerdictType] = None
    reason: str = ""
    impersonated_brand: Optional[str] = None
    risk_score: int = 0
    caveat: str = (
        "BaitBox's verdict is advice, not a guarantee. A 'Likely safe' result means "
        "nothing harmful was seen during one visit, not that the site is trustworthy."
    )
    hops: List[HopRecord] = Field(default_factory=list)
    final_screenshot_url: Optional[str] = None
    forms_detected: List[FormRecord] = Field(default_factory=list)
    downloads_quarantined: List[QuarantinedDownload] = Field(default_factory=list)
    egress_blocks: List[Dict[str, Any]] = Field(default_factory=list)
    agent_injection_findings: List[str] = Field(default_factory=list)
    rule_signals: List[RuleSignal] = Field(default_factory=list)
    containment_events: List[ContainmentEvent] = Field(default_factory=list)
    action_log: List[Dict[str, Any]] = Field(default_factory=list)
    chamber_receipt: Optional[ChamberLifecycleReceipt] = None
    pending_approval: Optional[PendingApprovalPrompt] = None
    model_used: str = ""
    inference_provider: str = "Vultr Serverless Inference (api.vultrinference.com/v1)"
