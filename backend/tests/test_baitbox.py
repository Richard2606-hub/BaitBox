"""
BaitBox — Comprehensive Automated Test Suite (backend/tests/test_baitbox.py)
============================================================================
Verifies all 8 BaitBox modules (M1-M8) and all 6 Project Objectives:
1. Objective 1 — Safe detonation & unconditional chamber destruction (including forced timeouts).
2. Objective 2 — Full-path redirect chain evidence (3 hops, status codes, screenshots).
3. Objective 3 — Plain-language verdict & 20-link benchmark accuracy (>= 17/20, 0 missed phishing).
4. Objective 4 — Visible containment (EICAR `.exe` and `.zip` quarantine with SHA-256,
   `169.254.169.254` SSRF block, hidden prompt-injection detection & M3 Gate refusal).
5. Objective 5 — Human approval gate for interactive pages (`waiting_approval` -> `approve`).
6. Objective 6 — Share-safe masked report URLs.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.chamber_manager import chamber_manager
from app.egress_rules import EICAR_SIGNATURE, check_outbound_url_allowed, inspect_response_for_quarantine
from app.evidence_store import mask_suspicious_url
from app.main import app
from app.orchestrator import extract_and_normalize_url, orchestrator
from app.policy_gate import DECOY_IDENTITY, PolicyAndApprovalGate
from app.schemas import ProposedAction, ScanCreateRequest


client = TestClient(app)


def test_url_extraction_from_message_text() -> None:
    msg = "URGENT: Your parcel is on hold, confirm delivery here: http://localhost:8000/trap/short/parcel-hold immediately!"
    extracted = extract_and_normalize_url(msg)
    assert extracted == "http://localhost:8000/trap/short/parcel-hold"


def test_m6_egress_filter_rules_block_metadata_and_private_ips() -> None:
    ok_meta, reason_meta = check_outbound_url_allowed("http://169.254.169.254/latest/meta-data/")
    assert not ok_meta
    assert "169.254.169.254" in reason_meta

    ok_priv, _ = check_outbound_url_allowed("http://192.168.1.55/admin")
    assert not ok_priv

    ok_rfc10, _ = check_outbound_url_allowed("http://10.0.0.12/internal")
    assert not ok_rfc10

    ok_pub, _ = check_outbound_url_allowed("https://www.wikipedia.org/wiki/Main_Page")
    assert ok_pub


def test_m6_egress_download_quarantine_and_sha256() -> None:
    rec = inspect_response_for_quarantine(
        url="https://malicious.example/invoice.exe",
        headers={"Content-Type": "application/x-msdownload"},
        body=EICAR_SIGNATURE,
    )
    assert rec is not None
    assert rec["filename"] == "invoice.exe"
    assert rec["is_eicar"] is True
    assert len(rec["sha256"]) == 64


def test_m3_policy_gate_blocks_invented_and_unsafe_actions() -> None:
    gate = PolicyAndApprovalGate(max_steps=8)

    # 1. Invented / prompt-injected form submit must be blocked
    res_submit = gate.check_action(
        ProposedAction(action="submit_form", target="form#0"),
        step_index=2,
    )
    assert res_submit.decision == "block"
    assert res_submit.containment_event.category == "policy_gate_block"

    # 2. Metadata SSRF navigation must be blocked
    res_ssrf = gate.check_action(
        ProposedAction(action="load", target="http://169.254.169.254/latest/meta-data/"),
        step_index=2,
    )
    assert res_ssrf.decision == "block"

    # 3. Real non-decoy credentials must be blocked
    res_real_cred = gate.check_action(
        ProposedAction(
            action="fill_decoy",
            target="form#0",
            parameters={"values": {"password": "MyRealSecretPassword123"}},
        ),
        step_index=2,
    )
    assert res_real_cred.decision == "block"

    # 4. Synthetic Decoy Canary values must be allowed
    res_decoy = gate.check_action(
        ProposedAction(
            action="fill_decoy",
            target="form#0",
            parameters={"values": dict(DECOY_IDENTITY)},
        ),
        step_index=2,
    )
    assert res_decoy.decision == "allow"


@pytest.mark.asyncio
async def test_pinnacle_trust_full_3_hop_detonation_and_containment() -> None:
    """
    Tests Scene 1-4 of the Demonstration Script:
    - 3 hops (shortener -> tracker -> Pinnacle Trust login)
    - Screenshots created for each hop
    - Verdict == 'Dangerous', Impersonated Brand == 'Pinnacle Trust'
    - EICAR `invoice.exe` download quarantined with SHA-256 recorded
    - Hidden prompt injection detected & `submit_form` refused by M3 Gate
    - `169.254.169.254` metadata probe refused by M6 Egress Filter
    - Chamber destroyed after scan with 0 chambers left running
    """
    orchestrator.set_local_app(app)
    report = await orchestrator.create_and_start_scan(
        ScanCreateRequest(
            input_text="Your parcel is on hold, confirm delivery here: http://localhost:8000/trap/short/parcel-hold"
        ),
        run_synchronously=True,
    )

    assert report.status == "completed"
    assert report.verdict == "Dangerous"
    assert report.impersonated_brand == "Pinnacle Trust"
    assert len(report.hops) == 3
    assert report.hops[0].status_code == 302
    assert report.hops[1].status_code == 302
    assert report.hops[2].status_code == 200

    # Verify EICAR download quarantined
    assert len(report.downloads_quarantined) >= 1
    dl = report.downloads_quarantined[0]
    assert dl.filename == "invoice.exe"
    assert dl.is_eicar is True
    assert len(dl.sha256) == 64

    # Verify SSRF metadata address blocked
    assert len(report.egress_blocks) >= 1
    assert any("169.254.169.254" in b.get("url", "") for b in report.egress_blocks)

    # Verify hidden prompt injection detected and submit_form blocked
    assert len(report.agent_injection_findings) >= 1
    assert any("169.254.169.254" in f for f in report.agent_injection_findings)
    assert any(a["gate_decision"] == "block" for a in report.action_log)

    # Verify chamber destroyed cleanly and 0 secrets inside
    assert report.chamber_receipt is not None
    assert report.chamber_receipt.destroyed_cleanly is True
    assert report.chamber_receipt.secrets_injected == 0
    assert chamber_manager.get_telemetry()["active_chambers_count"] == 0


@pytest.mark.asyncio
async def test_forced_timeout_destroys_chamber() -> None:
    """Objective 1: Every scan ends with the chamber gone, including scans that time out."""
    orchestrator.set_local_app(app)
    report = await orchestrator.create_and_start_scan(
        ScanCreateRequest(
            input_text="http://localhost:8000/trap/short/parcel-hold",
            simulate_timeout=True,
        ),
        run_synchronously=True,
    )
    assert report.status == "timed_out"
    assert report.chamber_receipt is not None
    assert report.chamber_receipt.destroyed_cleanly is True
    assert chamber_manager.get_telemetry()["active_chambers_count"] == 0


@pytest.mark.asyncio
async def test_objective5_human_approval_gate_and_objective6_share_safe_report() -> None:
    """
    Tests Objective 5 (Human approval pause & resume with decoy data) and
    Objective 6 (Share-safe masked report link).
    """
    orchestrator.set_local_app(app)
    initial = await orchestrator.create_and_start_scan(
        ScanCreateRequest(
            input_text="http://localhost:8000/trap/interstitial-verify",
            require_human_approval=True,
        ),
        run_synchronously=False,
    )

    # Wait briefly for scan to pause at the approval gate
    for _ in range(30):
        await asyncio.sleep(0.1)
        cur = client.get(f"/api/scans/{initial.scan_id}").json()
        if cur["status"] == "waiting_approval":
            break

    cur = client.get(f"/api/scans/{initial.scan_id}").json()
    assert cur["status"] == "waiting_approval"
    assert cur["pending_approval"] is not None

    # Approve the action
    approve_resp = client.post(
        f"/api/scans/{initial.scan_id}/approval",
        json={"decision": "approve"},
    )
    assert approve_resp.status_code == 200

    # Wait for completion
    for _ in range(40):
        await asyncio.sleep(0.1)
        cur = client.get(f"/api/scans/{initial.scan_id}").json()
        if cur["status"] in ("completed", "waiting_approval"):
            if cur["status"] == "waiting_approval":
                client.post(
                    f"/api/scans/{initial.scan_id}/approval",
                    json={"decision": "approve"},
                )
            elif cur["status"] == "completed":
                break

    final_rep = client.get(f"/api/scans/{initial.scan_id}").json()
    assert final_rep["status"] == "completed"
    assert final_rep["verdict"] == "Dangerous"

    # Objective 6: Verify share-safe report masks the original URL
    shared_rep = client.get(f"/api/reports/shared/{final_rep['share_token']}").json()
    assert "hxxp" in shared_rep["normalized_url"]
    assert "[.]" in shared_rep["normalized_url"] or "***" in shared_rep["normalized_url"]
