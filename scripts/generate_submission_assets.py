#!/usr/bin/env python3
"""
BaitBox — Submission Asset Generator (scripts/generate_submission_assets.py)
============================================================================
Renders the high-resolution 1920x1080 cover image (`docs/baitbox_cover.png`)
using Headless Chromium via Playwright for crisp typography and visual polish.
"""

from __future__ import annotations

from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT_DIR = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT_DIR / "docs"

COVER_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body {
      width: 1920px;
      height: 1080px;
      background: radial-gradient(circle at 15% 15%, #0f2942 0%, #090d16 55%, #05080f 100%);
      color: #f8fafc;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
    }
    .frame {
      width: 1800px;
      height: 960px;
      border-radius: 32px;
      background: rgba(15, 23, 42, 0.85);
      border: 3px solid rgba(34, 211, 238, 0.45);
      box-shadow: 0 30px 80px rgba(0, 0, 0, 0.65);
      padding: 64px 72px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .top-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 12px;
      padding: 10px 22px;
      border-radius: 999px;
      background: rgba(6, 182, 212, 0.15);
      border: 1.5px solid rgba(34, 211, 238, 0.5);
      color: #67e8f9;
      font-size: 18px;
      font-weight: 800;
      letter-spacing: 1px;
      text-transform: uppercase;
    }
    .vultr-badge {
      padding: 10px 22px;
      border-radius: 12px;
      background: rgba(59, 130, 246, 0.18);
      border: 1.5px solid rgba(96, 165, 250, 0.45);
      color: #bfdbfe;
      font-size: 18px;
      font-weight: 700;
    }
    .hero h1 {
      font-size: 86px;
      font-weight: 900;
      letter-spacing: -2px;
      line-height: 1.05;
      background: linear-gradient(90deg, #ffffff 0%, #67e8f9 55%, #38bdf8 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 14px;
    }
    .hero h2 {
      font-size: 36px;
      font-weight: 700;
      color: #e2e8f0;
      margin-bottom: 12px;
    }
    .hero p {
      font-size: 22px;
      color: #94a3b8;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 28px;
    }
    .card {
      background: rgba(9, 13, 22, 0.9);
      border-radius: 22px;
      padding: 30px;
      border: 2px solid #334155;
    }
    .card.blue { border-color: rgba(59, 130, 246, 0.6); }
    .card.red { border-color: rgba(239, 68, 68, 0.6); }
    .card.green { border-color: rgba(16, 185, 129, 0.6); }
    .card-title {
      font-size: 20px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      margin-bottom: 16px;
      padding-bottom: 12px;
      border-bottom: 1px solid #1e293b;
    }
    .card.blue .card-title { color: #60a5fa; }
    .card.red .card-title { color: #f87171; }
    .card.green .card-title { color: #34d399; }
    .card ul {
      list-style: none;
      space-y: 10px;
    }
    .card li {
      font-size: 18px;
      color: #cbd5e1;
      margin-bottom: 11px;
      line-height: 1.4;
    }
    .footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 17px;
      color: #64748b;
      border-top: 1px solid #1e293b;
      padding-top: 20px;
    }
  </style>
</head>
<body>
  <div class="frame">
    <div class="top-row">
      <div class="pill">Vultr Agent Rush Hackathon · Track 01: Blast Radius Zero (Pattern B)</div>
      <div class="vultr-badge">Powered by Vultr Cloud Compute &amp; Vultr Serverless Inference</div>
    </div>

    <div class="hero">
      <h1>BaitBox — Let the Box Take the Bait.</h1>
      <h2>A Disposable Detonation Chamber for Suspicious Links</h2>
      <p>Paste any suspicious link, SMS, or QR code. An AI browser agent visits it inside a throwaway container on Vultr and returns a plain-language verdict with screenshots and containment proof.</p>
    </div>

    <div class="grid">
      <div class="card blue">
        <div class="card-title">1. Trusted Control Plane (Vultr VM)</div>
        <ul>
          <li>✓ <strong>M1 Web Console:</strong> Next.js + Live SSE Progress</li>
          <li>✓ <strong>M2 Orchestrator:</strong> FastAPI 8-Step Agent Loop</li>
          <li>✓ <strong>M3 Policy Gate:</strong> Rule-Based Allow-List + Decoy ID</li>
          <li>✓ <strong>M4 Chamber Manager:</strong> 90s Timer + 60s Sweeper</li>
          <li>✓ <strong>M7 &amp; M8 Analyst &amp; Store:</strong> Quoted-Evidence LLM + SQLite</li>
          <li>✓ <strong>Secret Hygiene:</strong> Holds the ONLY Vultr API Key</li>
        </ul>
      </div>

      <div class="card red">
        <div class="card-title">2. Disposable Detonation Chamber</div>
        <ul>
          <li>✓ <strong>M5 Worker:</strong> Playwright + Headless Chromium</li>
          <li>✓ <strong>M6 Egress Filter:</strong> mitmproxy Only Route Out</li>
          <li>✓ <strong>Process Isolation:</strong> Non-Root (10001), Read-Only RootFS</li>
          <li>✓ <strong>Privilege Drop:</strong> cap_drop=ALL, no-new-privileges</li>
          <li>✓ <strong>Hard Ceilings:</strong> 1 vCPU · 1 GB RAM · 256 PIDs · 90s TTL</li>
          <li>✓ <strong>Zero Secrets:</strong> 0 Keys Inside · Destroyed After Scan</li>
        </ul>
      </div>

      <div class="card green">
        <div class="card-title">3. Verified Containment Proof</div>
        <ul>
          <li>✓ <strong>Verdict Accuracy:</strong> 20 / 20 (100.0%) on Benchmark</li>
          <li>✓ <strong>Dangerous Missed:</strong> 0 / 10 Phishing Pages Missed</li>
          <li>✓ <strong>Malware Blocked:</strong> 100% EICAR .exe &amp; .zip + SHA-256</li>
          <li>✓ <strong>SSRF Blocked:</strong> 100% 169.254.169.254 Metadata Refused</li>
          <li>✓ <strong>Prompt Injection:</strong> 0 Injected Actions Executed</li>
          <li>✓ <strong>Lifecycle Proof:</strong> 0 Chambers Left Running</li>
        </ul>
      </div>
    </div>

    <div class="footer">
      <span>Open-Source MIT License · Full 8-Module Implementation (M1–M8)</span>
      <span>api.vultrinference.com/v1 · Docker / gVisor (runsc) · Playwright · mitmproxy · Next.js · FastAPI</span>
    </div>
  </div>
</body>
</html>
"""


def generate_cover_image() -> Path:
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = DOCS_DIR / "baitbox_cover.png"
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1920, "height": 1080})
        page.set_content(COVER_HTML, wait_until="domcontentloaded")
        page.wait_for_timeout(100)
        page.screenshot(path=str(out_path), type="png")
        browser.close()
    return out_path


if __name__ == "__main__":
    p = generate_cover_image()
    print(f"Generated high-resolution Chromium cover image: {p}")
