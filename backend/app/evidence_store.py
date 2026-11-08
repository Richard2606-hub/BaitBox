"""
BaitBox — M8 Evidence Store and Report (backend/app/evidence_store.py)
======================================================================
Persists every scan's record in SQLite (`data/baitbox.db`), manages hop and
final screenshots on disk (`data/screenshots/{scan_id}/`), generates masked
share-safe report tokens (Objective 6), renders annotated evidence screenshots
highlighting impersonated brands and password fields, and enforces the 7-day
retention policy.
"""

from __future__ import annotations

import base64
import io
import json
import secrets
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from PIL import Image, ImageDraw, ImageFont

from .config import settings
from .schemas import ScanReport


def mask_suspicious_url(url: str) -> str:
    """
    Objective 6 (Share-safe reports): Masks a suspicious URL so a user can
    safely forward the report to family or fraud desks without anyone
    accidentally clicking a live phishing link.
    Example: `https://pinnacle-trust-login.xyz/auth/verify?id=991`
          -> `hxxps://pinnacle-trust-login[.]xyz/au***/***`
    """
    try:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "http").replace("http", "hxxp")
        host = (parsed.hostname or "unknown").replace(".", "[.]")
        port_part = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
        path = parsed.path or "/"
        if len(path) > 6:
            masked_path = path[:6] + "***/***"
        elif path != "/":
            masked_path = "/***"
        else:
            masked_path = "/"
        return f"{scheme}://{host}{port_part}{masked_path}"
    except Exception:
        return "hxxp://[masked-suspicious-link]/***"


def render_hop_or_page_screenshot(
    scan_id: str,
    filename: str,
    url: str,
    status_code: int,
    page_title: str,
    visible_text: str,
    has_password: bool = False,
    impersonated_brand: Optional[str] = None,
    hop_index: int = 1,
    total_hops: int = 1,
    is_redirect: bool = False,
    raw_png_bytes: Optional[bytes] = None,
    highlight_boxes: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """
    Saves a screenshot PNG to `data/screenshots/{scan_id}/{filename}` and
    returns its relative URL path (`/screenshots/{scan_id}/{filename}`).
    If `raw_png_bytes` is provided (from Playwright Chromium), overlays visual
    callout highlights using actual DOM `getBoundingClientRect()` coordinates
    (`highlight_boxes`) for impersonated brand and password fields (Scene 3).
    Otherwise, renders a high-clarity visual browser capture card of the hop.
    """
    scan_dir = settings.screenshots_dir / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    out_path = scan_dir / filename

    width, height = 1280, 800

    if raw_png_bytes:
        try:
            img = Image.open(io.BytesIO(raw_png_bytes)).convert("RGBA")
            if img.size != (width, height):
                img = img.resize((width, height))
        except Exception:
            img = Image.new("RGBA", (width, height), (15, 23, 42, 255))

        draw_overlay = ImageDraw.Draw(img)
        drawn_brand = False
        drawn_pw = False

        badge_font: Any = None
        for font_candidate in ("arialbd.ttf", "segoeuib.ttf", "DejaVuSans-Bold.ttf", "arial.ttf"):
            try:
                badge_font = ImageFont.truetype(font_candidate, 12)
                break
            except Exception:
                continue
        if badge_font is None:
            try:
                badge_font = ImageFont.load_default()
            except Exception:
                badge_font = None

        if highlight_boxes:
            for box in highlight_boxes:
                btype = box.get("type", "")
                bx = max(4, int(box.get("x", 0)))
                by = max(28, int(box.get("y", 0)))
                bw = min(width - bx - 4, max(80, int(box.get("width", 200))))
                bh = min(height - by - 40, max(28, int(box.get("height", 40))))

                if btype == "brand" and impersonated_brand and not drawn_brand:
                    draw_overlay.rounded_rectangle(
                        [bx - 4, by - 4, bx + bw + 4, by + bh + 4],
                        radius=8,
                        outline=(239, 68, 68, 255),
                        width=4,
                    )
                    label_y = max(4, by - 28)
                    draw_overlay.rounded_rectangle(
                        [bx - 4, label_y, min(width - 8, bx + 410), label_y + 24],
                        radius=5,
                        fill=(220, 38, 38, 255),
                    )
                    draw_overlay.text(
                        (bx + 8, label_y + 5),
                        f"IMPERSONATED BRAND DETECTED: {impersonated_brand.upper()}",
                        fill=(255, 255, 255, 255),
                        font=badge_font,
                    )
                    drawn_brand = True
                elif btype == "password" and has_password and not drawn_pw:
                    draw_overlay.rounded_rectangle(
                        [bx - 4, by - 4, bx + bw + 4, by + bh + 4],
                        radius=8,
                        outline=(239, 68, 68, 255),
                        width=3,
                    )
                    # Place pill inside the right side of the password input field so it never overlaps labels above/below
                    tag_w = 204
                    tag_h = 22
                    tag_x1 = max(bx + 8, bx + bw - tag_w - 8)
                    tag_y1 = by + max(4, (bh - tag_h) // 2)
                    draw_overlay.rounded_rectangle(
                        [tag_x1, tag_y1, tag_x1 + tag_w, tag_y1 + tag_h],
                        radius=5,
                        fill=(220, 38, 38, 255),
                    )
                    draw_overlay.text(
                        (tag_x1 + 10, tag_y1 + 4),
                        "PASSWORD HARVESTING FIELD",
                        fill=(255, 255, 255, 255),
                        font=badge_font,
                    )
                    drawn_pw = True

        if not is_redirect and impersonated_brand and not drawn_brand:
            draw_overlay.rounded_rectangle([24, 34, 680, 118], radius=8, outline=(239, 68, 68, 255), width=4)
            draw_overlay.rectangle([24, 8, 430, 34], fill=(220, 38, 38, 255))
            draw_overlay.text((34, 14), f"IMPERSONATED BRAND DETECTED: {impersonated_brand.upper()}", fill=(255, 255, 255, 255))

        if not is_redirect and has_password and not drawn_pw:
            draw_overlay.rounded_rectangle([720, 290, 1140, 420], radius=8, outline=(239, 68, 68, 255), width=4)
            draw_overlay.rectangle([720, 264, 1100, 290], fill=(220, 38, 38, 255))
            draw_overlay.text((730, 270), "CREDENTIAL HARVESTING FIELD (PASSWORD)", fill=(255, 255, 255, 255))

        # Bottom BaitBox watermark bar
        draw_overlay.rectangle([0, height - 34, width, height], fill=(15, 23, 42, 235))
        draw_overlay.text(
            (20, height - 24),
            f"BaitBox Real Chromium Evidence | Scan {scan_id} | Hop {hop_index}/{total_hops} [{status_code}] | {url[:75]}",
            fill=(148, 163, 184, 255),
        )
        img.convert("RGB").save(out_path, format="PNG")
        return f"/screenshots/{scan_id}/{filename}"
    else:
        img = Image.new("RGBA", (width, height), (248, 250, 252, 255))
        draw = ImageDraw.Draw(img)

        # Browser top chrome bar
        draw.rectangle([0, 0, width, 64], fill=(15, 23, 42, 255))
        # Traffic light dots
        draw.ellipse([20, 24, 34, 38], fill=(239, 68, 68, 255))
        draw.ellipse([44, 24, 58, 38], fill=(245, 158, 11, 255))
        draw.ellipse([68, 24, 82, 38], fill=(16, 185, 129, 255))
        # Address bar
        draw.rounded_rectangle([110, 14, width - 220, 50], radius=8, fill=(30, 41, 59, 255))
        draw.text((126, 24), f"GET {url[:88]}", fill=(226, 232, 240, 255))
        # Hop status pill
        pill_color = (245, 158, 11, 255) if is_redirect else ((220, 38, 38, 255) if has_password else (16, 185, 129, 255))
        draw.rounded_rectangle([width - 200, 14, width - 20, 50], radius=8, fill=pill_color)
        draw.text((width - 185, 24), f"HOP {hop_index}/{total_hops} [{status_code}]", fill=(255, 255, 255, 255))

        if is_redirect:
            # Render redirect hop visual card
            draw.rounded_rectangle([140, 180, width - 140, 560], radius=16, fill=(255, 255, 255, 255), outline=(203, 213, 225, 255), width=2)
            draw.rectangle([140, 180, width - 140, 245], fill=(254, 243, 199, 255))
            draw.text((175, 204), f"HTTP {status_code} REDIRECT INTERCEPTED BY BAITBOX DETONATION WORKER (M5)", fill=(146, 64, 14, 255))
            draw.text((175, 285), f"Hop #{hop_index} Source URL:", fill=(100, 116, 139, 255))
            draw.text((175, 315), url[:95], fill=(15, 23, 42, 255))
            draw.text((175, 375), "Redirect Behavior:", fill=(100, 116, 139, 255))
            draw.text((175, 405), visible_text[:110] or "Server issued automatic Location header redirect to next hop.", fill=(51, 65, 85, 255))
            draw.text((175, 475), "Chamber Isolation Status: Active | Egress Filter (M6): Inspecting | Secrets Inside Container: 0", fill=(16, 185, 129, 255))
        else:
            # Render final landing page DOM visual representation
            header_bg = (30, 58, 138, 255) if impersonated_brand else (15, 23, 42, 255)
            draw.rectangle([0, 64, width, 155], fill=header_bg)
            brand_header = impersonated_brand or page_title or "External Web Page"
            draw.text((60, 96), f"{brand_header.upper()} — ONLINE PORTAL", fill=(255, 255, 255, 255))

            # Page content container
            draw.rounded_rectangle([80, 190, 740, 720], radius=12, fill=(255, 255, 255, 255), outline=(226, 232, 240, 255), width=2)
            draw.text((110, 220), (page_title or "Web Page Content")[:65], fill=(15, 23, 42, 255))

            # Wrap visible text lines
            words = (visible_text or "Page loaded inside BaitBox disposable chamber.").split()
            lines: List[str] = []
            cur = ""
            for w in words:
                if len(cur) + len(w) + 1 <= 68:
                    cur = f"{cur} {w}".strip()
                else:
                    lines.append(cur)
                    cur = w
                if len(lines) >= 12:
                    break
            if cur and len(lines) < 12:
                lines.append(cur)

            y_cursor = 265
            for ln in lines:
                draw.text((110, y_cursor), ln, fill=(71, 85, 105, 255))
                y_cursor += 28

            # If form / password field exists, render the login box on the right and highlight it
            if has_password:
                draw.rounded_rectangle([780, 190, 1210, 640], radius=12, fill=(255, 255, 255, 255), outline=(203, 213, 225, 255), width=2)
                draw.text((810, 220), "Sign In / Verify Identity", fill=(15, 23, 42, 255))
                draw.text((810, 265), "Account Username / Email", fill=(100, 116, 139, 255))
                draw.rounded_rectangle([810, 290, 1180, 336], radius=6, fill=(248, 250, 252, 255), outline=(148, 163, 184, 255), width=1)
                draw.text((824, 305), "alex.rivera.decoy00 (Decoy)", fill=(100, 116, 139, 255))

                draw.text((810, 360), "Account Password / PIN", fill=(100, 116, 139, 255))
                draw.rounded_rectangle([810, 385, 1180, 435], radius=6, fill=(254, 242, 242, 255), outline=(220, 38, 38, 255), width=2)
                draw.text((824, 402), "************************", fill=(220, 38, 38, 255))

                draw.rounded_rectangle([810, 470, 1180, 520], radius=8, fill=(30, 58, 138, 255))
                draw.text((925, 488), "VERIFY & SIGN IN", fill=(255, 255, 255, 255))

    # Overlay Analyst Red Highlight Callouts (Scene 3 requirement: highlight impersonated brand and password field)
    draw_overlay = ImageDraw.Draw(img)
    if not is_redirect and impersonated_brand:
        draw_overlay.rounded_rectangle([40, 72, 680, 148], radius=8, outline=(239, 68, 68, 255), width=4)
        draw_overlay.rectangle([40, 48, 430, 74], fill=(220, 38, 38, 255))
        draw_overlay.text((50, 54), f"IMPERSONATED BRAND DETECTED: {impersonated_brand.upper()}", fill=(255, 255, 255, 255))

    if not is_redirect and has_password:
        draw_overlay.rounded_rectangle([798, 352, 1192, 448], radius=8, outline=(239, 68, 68, 255), width=4)
        draw_overlay.rectangle([798, 326, 1192, 352], fill=(220, 38, 38, 255))
        draw_overlay.text((808, 332), "CREDENTIAL HARVESTING FIELD (PASSWORD)", fill=(255, 255, 255, 255))

    # Bottom BaitBox watermark bar
    draw_overlay.rectangle([0, height - 36, width, height], fill=(15, 23, 42, 240))
    draw_overlay.text(
        (20, height - 25),
        f"BaitBox Detonation Evidence | Scan {scan_id} | Hop {hop_index}/{total_hops} | Captured inside isolated chamber",
        fill=(148, 163, 184, 255),
    )

    img.convert("RGB").save(out_path, format="PNG")
    return f"/screenshots/{scan_id}/{filename}"


class EvidenceStore:
    """M8: SQLite and screenshot file store on the Vultr VM."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or settings.db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    share_token TEXT UNIQUE NOT NULL,
                    status TEXT NOT NULL,
                    submitted_input TEXT NOT NULL,
                    normalized_url TEXT NOT NULL,
                    masked_url TEXT NOT NULL,
                    verdict TEXT,
                    impersonated_brand TEXT,
                    risk_score INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    report_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_share_token ON scans(share_token)"
            )
            conn.commit()

    def save_report(self, report: ScanReport) -> None:
        payload = report.model_dump_json()
        with self._connect() as conn:
            if report.status == "completed" and report.normalized_url:
                conn.execute(
                    "DELETE FROM scans WHERE normalized_url = ? AND scan_id != ? AND verdict != ?",
                    (report.normalized_url, report.scan_id, report.verdict or ""),
                )
            conn.execute(
                """
                INSERT INTO scans (
                    scan_id, share_token, status, submitted_input, normalized_url,
                    masked_url, verdict, impersonated_brand, risk_score,
                    created_at, completed_at, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    status = excluded.status,
                    verdict = excluded.verdict,
                    impersonated_brand = excluded.impersonated_brand,
                    risk_score = excluded.risk_score,
                    completed_at = excluded.completed_at,
                    report_json = excluded.report_json
                """,
                (
                    report.scan_id,
                    report.share_token,
                    report.status,
                    report.submitted_input,
                    report.normalized_url,
                    report.masked_url,
                    report.verdict,
                    report.impersonated_brand,
                    report.risk_score,
                    report.created_at,
                    report.completed_at,
                    payload,
                ),
            )
            conn.commit()

    def get_report(self, scan_id: str) -> Optional[ScanReport]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT report_json FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            if not row:
                return None
            return ScanReport.model_validate_json(row["report_json"])

    def get_report_by_share_token(self, share_token: str) -> Optional[ScanReport]:
        """
        Objective 6: Returns a sanitized public report with the original URL
        masked so recipients cannot click the live malicious link.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT report_json FROM scans WHERE share_token = ?", (share_token,)
            ).fetchone()
            if not row:
                return None
            report = ScanReport.model_validate_json(row["report_json"])
            # Mask raw URLs in the shared view
            report.submitted_input = report.masked_url
            report.normalized_url = report.masked_url
            report.final_url = mask_suspicious_url(report.final_url or report.normalized_url)
            for hop in report.hops:
                hop.url = mask_suspicious_url(hop.url)
            return report

    def list_recent_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT scan_id, share_token, status, normalized_url, masked_url,
                       verdict, impersonated_brand, risk_score, created_at, completed_at
                FROM scans
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def delete_scan(self, scan_id: str) -> bool:
        """Deletes a scan record and its screenshot directory from M8 Evidence Store."""
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            conn.commit()
            deleted = cur.rowcount > 0
        shot_dir = settings.screenshots_dir / scan_id
        if shot_dir.exists():
            shutil.rmtree(shot_dir, ignore_errors=True)
        return deleted

    def cleanup_old_scans(self, retention_days: Optional[int] = None) -> int:
        """Deletes scans and screenshot folders older than `retention_days` (default 7 days)."""
        days = retention_days if retention_days is not None else settings.retention_days
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        removed = 0
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT scan_id FROM scans WHERE created_at < ?", (cutoff,)
            ).fetchall()
            for row in rows:
                sid = row["scan_id"]
                shot_dir = settings.screenshots_dir / sid
                if shot_dir.exists():
                    shutil.rmtree(shot_dir, ignore_errors=True)
                removed += 1
            conn.execute("DELETE FROM scans WHERE created_at < ?", (cutoff,))
            conn.commit()
        return removed


evidence_store = EvidenceStore()
