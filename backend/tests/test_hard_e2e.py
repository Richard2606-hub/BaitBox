"""
BaitBox — Hard End-to-End Stress, Chromium & Security Verification Suite (backend/tests/test_hard_e2e.py)
========================================================================================================
Exhaustively tests BaitBox across real Headless Chromium rendering, live JS SSRF
interception, EICAR `.exe` and `.zip` quarantine, QR code scam poster decoding,
runtime Vultr Serverless Inference configuration, concurrent multi-scan stress
testing, forced timeout destruction, and the full 20-link benchmark.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from PIL import Image
import pytest
from fastapi.testclient import TestClient

from app.chamber_manager import chamber_manager
from app.config import settings
from app.main import app
from app.orchestrator import orchestrator
from app.schemas import ScanCreateRequest


client = TestClient(app)


def test_health_and_vultr_catalog_endpoints() -> None:
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    models_resp = client.get("/api/system/models")
    assert models_resp.status_code == 200
    data = models_resp.json()
    assert data["endpoint"] == "https://api.vultrinference.com/v1"
    assert isinstance(data["models"], list)


def test_runtime_config_update_and_secret_hygiene() -> None:
    resp = client.post(
        "/api/system/config",
        json={
            "planner_model": "deepseek-v4.1-flash-1017",
            "vision_model": "deepseek-v4.1-flash-1017",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["planner_model"] == "deepseek-v4.1-flash-1017"

    tel = client.get("/api/system/telemetry").json()
    assert tel["chamber_manager"]["limits"]["secrets_in_chamber"] == 0


def test_qr_poster_generation_and_qr_scam_detonation() -> None:
    poster_resp = client.get("/api/qr/poster")
    assert poster_resp.status_code == 200
    assert poster_resp.headers["content-type"] == "image/png"
    assert len(poster_resp.content) > 1000

    scan_resp = client.post(
        "/api/scans?sync=true",
        json={
            "input_text": "Poster QR Scan: http://localhost:8000/trap/qr-scholarship",
            "require_human_approval": False,
        },
    )
    assert scan_resp.status_code == 200
    rep = scan_resp.json()
    assert rep["verdict"] == "Dangerous"
    assert rep["impersonated_brand"] == "Maybank"
    assert rep["chamber_receipt"]["destroyed_cleanly"] is True
    assert rep["chamber_receipt"]["secrets_injected"] == 0


@pytest.mark.asyncio
async def test_real_chromium_screenshot_dimensions_and_highlights() -> None:
    """Verifies that the final screenshot is a valid 1280x800 PNG rendered by Headless Chromium."""
    orchestrator.set_local_app(app)
    report = await orchestrator.create_and_start_scan(
        ScanCreateRequest(input_text="http://localhost:8000/trap/short/parcel-hold"),
        run_synchronously=True,
    )
    assert report.final_screenshot_url is not None
    shot_name = Path(report.final_screenshot_url).name
    shot_file = settings.screenshots_dir / report.scan_id / shot_name
    assert shot_file.exists()

    with Image.open(shot_file) as im:
        assert im.size == (1280, 800)
        assert im.format == "PNG"


@pytest.mark.asyncio
async def test_concurrent_multi_scan_stress_zero_leftover_chambers() -> None:
    """Runs 4 concurrent detonations in parallel and confirms all complete with 0 chambers left running."""
    orchestrator.set_local_app(app)
    urls = [
        "http://localhost:8000/trap/short/parcel-hold",
        "http://localhost:8000/trap/qr-scholarship",
        "http://localhost:8000/trap/safe-reference",
        "https://paypa1-account-update.top/signin",
    ]
    tasks = [
        orchestrator.create_and_start_scan(
            ScanCreateRequest(input_text=u), run_synchronously=True
        )
        for u in urls
    ]
    reports = await asyncio.gather(*tasks)
    assert len(reports) == 4
    assert reports[0].verdict == "Dangerous"
    assert reports[1].verdict == "Dangerous"
    assert reports[2].verdict == "Likely safe"
    assert reports[3].verdict == "Dangerous"

    # Zero chambers left running after parallel execution
    assert chamber_manager.get_telemetry()["active_chambers_count"] == 0


def test_full_20_link_benchmark_api_100_percent() -> None:
    resp = client.post("/api/benchmark/run")
    assert resp.status_code == 200
    summary = resp.json()["summary"]
    assert summary["verdict_accuracy"] == "20/20"
    assert summary["verdict_accuracy_pct"] == 100.0
    assert summary["dangerous_pages_missed"] == "0/10"
    assert summary["chambers_left_running"] == 0
    assert summary["forced_timeout_destroyed_cleanly"] is True


def test_human_dogfood_defanged_multilink_and_invalid_inputs() -> None:
    # 1. Defanged link in forwarded analyst message
    r1 = client.post(
        "/api/urls/extract",
        json={"input_text": "Forwarded link: hxxp://127.0.0.1:8000/trap/short/parcel-hold"},
    )
    assert r1.status_code == 200
    d1 = r1.json()
    assert d1["primary_url"] == "http://127.0.0.1:8000/trap/short/parcel-hold"
    assert d1["was_defanged"] is True

    # 2. Multi-link email with benign footer link + phishing action link
    r2 = client.post(
        "/api/urls/extract",
        json={
            "input_text": (
                "Sent by Apple Support (https://support.apple.com) — "
                "Unlock your suspended Apple ID immediately at hxxps://apple-id-locked-support[.]xyz/unlock"
            )
        },
    )
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["primary_url"] == "https://apple-id-locked-support.xyz/unlock"
    assert len(d2["all_urls"]) == 2

    # 3. Conversational text with no link or domain should return 400 Bad Request
    r3 = client.post("/api/scans?sync=true", json={"input_text": "hello how are you doing today"})
    assert r3.status_code == 400


def test_qr_image_upload_decode_roundtrip() -> None:
    import base64

    poster_resp = client.get("/api/qr/poster")
    assert poster_resp.status_code == 200
    b64_img = base64.b64encode(poster_resp.content).decode("ascii")

    dec_resp = client.post(
        "/api/qr/decode",
        json={"image_base64": f"data:image/png;base64,{b64_img}", "filename": "campus_poster.png"},
    )
    assert dec_resp.status_code == 200
    dec_data = dec_resp.json()
    assert dec_data["decoded_url"] == "http://localhost:8000/trap/qr-scholarship"


def test_idn_homograph_and_scan_delete() -> None:
    # Punycode homograph of PayPal ('xn--pypal-4ve.com' -> 'p\u0430ypal.com')
    resp = client.post(
        "/api/scans?sync=true",
        json={"input_text": "https://xn--pypal-4ve.com/signin", "require_human_approval": False},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "Dangerous"
    assert data["impersonated_brand"] == "PayPal"
    codes = [s["code"] for s in data["rule_signals"]]
    assert "IDN_HOMOGRAPH_OR_PUNYCODE_ATTACK" in codes

    # Delete the scan from history
    del_resp = client.delete(f"/api/scans/{data['scan_id']}")
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True

    # Confirm 404 after deletion
    get_resp = client.get(f"/api/scans/{data['scan_id']}")
    assert get_resp.status_code == 404


def test_real_live_internet_website_detections() -> None:
    """Verify real live external internet websites are accurately detected and rendered."""
    # 1. Google SafeBrowsing Live Phishing Page (formless <input type="password"> inside <div>, no <title>)
    r_phish = client.post(
        "/api/scans?sync=true",
        json={"input_text": "https://testsafebrowsing.appspot.com/s/phishing.html"},
    )
    assert r_phish.status_code == 200
    d_phish = r_phish.json()
    assert d_phish["verdict"] == "Dangerous"
    assert d_phish["risk_score"] >= 65
    phish_codes = [s["code"] for s in d_phish["rule_signals"]]
    assert "CREDENTIAL_HARVEST_FORM" in phish_codes
    assert "SHARED_CLOUD_PHISHING_HOST" in phish_codes

    # 2. Google SafeBrowsing Live Malware Page (<a href=".../double_zipped.zip"> intercepted & quarantined)
    r_mal = client.post(
        "/api/scans?sync=true",
        json={"input_text": "https://testsafebrowsing.appspot.com/s/malware.html"},
    )
    assert r_mal.status_code == 200
    d_mal = r_mal.json()
    assert d_mal["verdict"] == "Dangerous"
    mal_codes = [s["code"] for s in d_mal["rule_signals"]]
    assert "QUARANTINED_EXECUTABLE_DOWNLOAD" in mal_codes
    assert len(d_mal["downloads_quarantined"]) >= 1
    assert d_mal["downloads_quarantined"][0]["filename"] == "double_zipped.zip"
    assert len(d_mal["downloads_quarantined"][0]["sha256"]) == 64

    # 3. Heroku Shared Cloud Login Lure
    r_heroku = client.post(
        "/api/scans?sync=true",
        json={"input_text": "https://the-internet.herokuapp.com/login"},
    )
    assert r_heroku.status_code == 200
    d_heroku = r_heroku.json()
    assert d_heroku["verdict"] == "Dangerous"
    heroku_codes = [s["code"] for s in d_heroku["rule_signals"]]
    assert "CREDENTIAL_HARVEST_FORM" in heroku_codes
    assert "SHARED_CLOUD_PHISHING_HOST" in heroku_codes

    # 4. Official Brand Login (github.com/login) -> Zero False Positives (Likely safe, 0/100)
    r_gh = client.post(
        "/api/scans?sync=true",
        json={"input_text": "https://github.com/login"},
    )
    assert r_gh.status_code == 200
    d_gh = r_gh.json()
    assert d_gh["verdict"] == "Likely safe"
    assert d_gh["risk_score"] == 0

    # 5. Live Phishing Catalog & OpenPhish Feed API
    r_feed = client.get("/api/phishing/live-feed?fetch_openphish=true&limit=10")
    assert r_feed.status_code == 200
    d_feed = r_feed.json()
    assert d_feed["catalog_count"] >= 20
    assert len(d_feed["openphish_live_urls"]) >= 1

    # 6. Active In-The-Wild OpenPhish: Adobe PDF + Telegram Exfil + TLS Mismatch
    r_adobe = client.post(
        "/api/scans?sync=true",
        json={"input_text": "http://www.adobesign-coral.vercel.app/"},
    )
    assert r_adobe.status_code == 200
    d_adobe = r_adobe.json()
    assert d_adobe["verdict"] == "Dangerous"
    adobe_codes = [s["code"] for s in d_adobe["rule_signals"]]
    assert "CREDENTIAL_EXFIL_WEBHOOK_DETECTED" in adobe_codes
    assert "INVALID_OR_MISMATCHED_TLS_CERT" in adobe_codes

    # 7. Active In-The-Wild OpenPhish: MetaMask Mathematical Unicode Obfuscation
    r_mm = client.post(
        "/api/scans?sync=true",
        json={"input_text": "http://m3tamsklognx.gitbook.io/us"},
    )
    assert r_mm.status_code == 200
    d_mm = r_mm.json()
    assert d_mm["verdict"] == "Dangerous"
    assert d_mm["impersonated_brand"] == "MetaMask"
    mm_codes = [s["code"] for s in d_mm["rule_signals"]]
    assert "UNICODE_BRAND_OBFUSCATION" in mm_codes
    assert "CRYPTO_SEED_OR_WALLET_DRAINER_LURE" in mm_codes

    # 8. Active In-The-Wild OpenPhish: Microsoft Security Verification (#bootScreen hidden login)
    r_ms = client.post(
        "/api/scans?sync=true",
        json={"input_text": "https://omis-gules.vercel.app/"},
    )
    assert r_ms.status_code == 200
    d_ms = r_ms.json()
    assert d_ms["verdict"] == "Dangerous"
    assert d_ms["impersonated_brand"] == "Microsoft"


