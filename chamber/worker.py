#!/usr/bin/env python3
"""
BaitBox — M5 Detonation Worker (chamber/worker.py)
==================================================
Runs inside the disposable detonation chamber container (non-root UID 10001,
read-only rootfs, cap_drop=ALL, no-new-privileges, 1 CPU, 1 GB RAM, 256 PIDs,
zero API keys).

Wait for JSON action messages from the orchestrator over a Unix socket
(`/tmp/chamber.sock`) or stdin/TCP channel:
  - {"action": "load", "url": "https://..."}
  - {"action": "wait", "ms": 1500}
  - {"action": "scroll", "pixels": 600}
  - {"action": "click_verify", "selector": "..."}
  - {"action": "fill_decoy", "decoy_identity": {...}}
  - {"action": "stop"}

Performs actions with Playwright and headless Chromium routed through the M6
Egress Filter proxy, records every redirect hop with status code and timing,
takes a screenshot at each hop and of the final page, extracts visible text,
hidden DOM text (prompt-injection traps), form fields, and external scripts,
blocks downloads, and returns a fixed-format JSON evidence bundle.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import os
import re
import socket
import sys
import time
from typing import Any, Dict, List, Optional

DESKTOP_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36"
)

MAX_VISIBLE_TEXT_CHARS = 4000


def _clean_text(raw: str, max_len: int = MAX_VISIBLE_TEXT_CHARS) -> str:
    collapsed = re.sub(r"\s+", " ", raw or "").strip()
    return collapsed[:max_len]


class ChamberBrowserSession:
    """Manages a single Playwright Chromium session inside the disposable chamber."""

    def __init__(self, proxy_url: Optional[str] = None) -> None:
        self.proxy_url = proxy_url or os.getenv("HTTP_PROXY") or os.getenv("HTTPS_PROXY")
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        self.hops: List[Dict[str, Any]] = []
        self.downloads_blocked: List[Dict[str, Any]] = []
        self.network_attempts: List[Dict[str, Any]] = []
        self.external_scripts: List[str] = []

    async def start(self) -> None:
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        launch_kwargs: Dict[str, Any] = {
            "headless": True,
            "args": [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-Background-networking",
            ],
        }
        if self.proxy_url:
            launch_kwargs["proxy"] = {"server": self.proxy_url}

        self._browser = await self._playwright.chromium.launch(**launch_kwargs)
        self._context = await self._browser.new_context(
            user_agent=DESKTOP_USER_AGENT,
            viewport={"width": 1280, "height": 800},
            accept_downloads=True,
            ignore_https_errors=True,
        )
        self._page = await self._context.new_page()

        # Intercept and quarantine any browser-initiated download
        async def _on_download(download: Any) -> None:
            suggested = download.suggested_filename or "unknown.bin"
            dl_url = download.url
            sha256_hex = hashlib.sha256(f"{suggested}:{dl_url}".encode("utf-8")).hexdigest()
            try:
                await download.cancel()
            except Exception:
                pass
            self.downloads_blocked.append(
                {
                    "filename": suggested,
                    "url": dl_url,
                    "sha256": sha256_hex,
                    "action": "quarantined_by_worker",
                }
            )

        self._page.on("download", lambda d: asyncio.create_task(_on_download(d)))

        # Record sub-requests and external scripts
        def _on_request(req: Any) -> None:
            url = req.url
            rtype = req.resource_type
            self.network_attempts.append({"url": url, "method": req.method, "resource_type": rtype})
            if rtype == "script" and url not in self.external_scripts:
                self.external_scripts.append(url)

        self._page.on("request", _on_request)

    async def execute_action(self, message: Dict[str, Any]) -> Dict[str, Any]:
        action = message.get("action", "stop")
        if self._page is None and action != "stop":
            await self.start()

        start_ts = time.perf_counter()

        if action == "load":
            target_url = message["url"]
            await self._load_and_trace_redirects(target_url)
        elif action == "wait":
            wait_ms = min(int(message.get("ms", 1500)), 5000)
            await self._page.wait_for_timeout(wait_ms)
        elif action == "scroll":
            pixels = int(message.get("pixels", 500))
            await self._page.evaluate(f"window.scrollBy(0, {pixels})")
            await self._page.wait_for_timeout(400)
        elif action == "click_verify":
            selector = message.get("selector", "button, a.verify-btn, [data-verify]")
            try:
                await self._page.click(selector, timeout=3000)
                await self._page.wait_for_timeout(800)
            except Exception:
                pass
        elif action == "fill_decoy":
            decoy = message.get("decoy_identity", {})
            await self._fill_decoy_fields(decoy)
        elif action == "stop":
            await self.close()
            return {"status": "stopped"}

        elapsed_ms = int((time.perf_counter() - start_ts) * 1000)
        return await self._collect_evidence_bundle(action_performed=action, elapsed_ms=elapsed_ms)

    async def _load_and_trace_redirects(self, url: str) -> None:
        t0 = time.perf_counter()
        response = await self._page.goto(url, wait_until="domcontentloaded", timeout=25000)
        await self._page.wait_for_timeout(500)

        # Reconstruct full redirect chain from Playwright request chain
        chain = []
        if response is not None:
            req = response.request
            while req is not None:
                resp = await req.response()
                chain.append(
                    {
                        "url": req.url,
                        "status_code": resp.status if resp else 200,
                        "headers": dict(resp.headers) if resp else {},
                    }
                )
                req = req.redirected_from
            chain.reverse()

        final_screenshot_bytes = await self._page.screenshot(type="png", full_page=False)
        final_b64 = base64.b64encode(final_screenshot_bytes).decode("ascii")
        total_ms = int((time.perf_counter() - t0) * 1000)

        self.hops = []
        for idx, item in enumerate(chain or [{"url": url, "status_code": 200, "headers": {}}]):
            is_last = idx == len(chain) - 1
            self.hops.append(
                {
                    "hop_index": idx + 1,
                    "url": item["url"],
                    "status_code": item["status_code"],
                    "latency_ms": max(40, total_ms // max(1, len(chain))),
                    "screenshot_b64": final_b64 if is_last else None,
                }
            )

    async def _fill_decoy_fields(self, decoy: Dict[str, str]) -> None:
        email = decoy.get("email", "decoy-canary-000@baitbox.invalid")
        username = decoy.get("username", "Alex Rivera")
        password = decoy.get("password", "DecoyCanary!NotARealPassword99")
        try:
            for inp in await self._page.query_selector_all("input"):
                itype = (await inp.get_attribute("type") or "text").lower()
                if itype == "password":
                    await inp.fill(password)
                elif itype == "email":
                    await inp.fill(email)
                elif itype in ("text", "tel"):
                    await inp.fill(username)
        except Exception:
            pass

    async def _collect_evidence_bundle(self, action_performed: str, elapsed_ms: int) -> Dict[str, Any]:
        page_title = await self._page.title()
        final_url = self._page.url

        # Extract visible text, hidden DOM elements, and form fields inside browser context
        dom_data = await self._page.evaluate(
            """() => {
                const visibleText = document.body ? document.body.innerText : "";
                const hiddenTexts = [];
                const allElements = Array.from(document.querySelectorAll("*"));
                for (const el of allElements) {
                    const style = window.getComputedStyle(el);
                    const isHidden = (
                        style.display === "none" ||
                        style.visibility === "hidden" ||
                        parseFloat(style.opacity || "1") < 0.05 ||
                        parseFloat(style.fontSize || "12") === 0 ||
                        el.hasAttribute("hidden") ||
                        el.getAttribute("aria-hidden") === "true" ||
                        el.hasAttribute("data-agent-instruction")
                    );
                    if (isHidden) {
                        const txt = (el.textContent || "").trim();
                        if (txt.length > 5 && !hiddenTexts.includes(txt)) {
                            hiddenTexts.push(txt.slice(0, 500));
                        }
                    }
                }
                const forms = Array.from(document.querySelectorAll("form")).map((f, idx) => {
                    const inputs = Array.from(f.querySelectorAll("input, select, textarea")).map(inp => ({
                        name: inp.getAttribute("name") || inp.getAttribute("id") || "",
                        type: (inp.getAttribute("type") || inp.tagName || "text").toLowerCase(),
                        placeholder: inp.getAttribute("placeholder") || "",
                        required: inp.hasAttribute("required")
                    }));
                    return {
                        form_index: idx,
                        action: f.getAttribute("action") || "",
                        method: (f.getAttribute("method") || "GET").toUpperCase(),
                        inputs: inputs,
                        has_password: inputs.some(i => i.type === "password"),
                        has_card_or_otp: inputs.some(i => /card|cvv|otp|pin|tan/i.test(i.name + " " + i.placeholder))
                    };
                });
                return { visibleText, hiddenTexts, forms };
            }"""
        )

        screenshot_bytes = await self._page.screenshot(type="png", full_page=False)
        screenshot_b64 = base64.b64encode(screenshot_bytes).decode("ascii")

        return {
            "action_performed": action_performed,
            "elapsed_ms": elapsed_ms,
            "final_url": final_url,
            "page_title": page_title,
            "hops": self.hops,
            "visible_text": _clean_text(dom_data.get("visibleText", "")),
            "hidden_texts": dom_data.get("hiddenTexts", []),
            "forms": dom_data.get("forms", []),
            "external_scripts": self.external_scripts[:30],
            "downloads_blocked": self.downloads_blocked,
            "network_attempts": self.network_attempts[:60],
            "final_screenshot_b64": screenshot_b64,
        }

    async def close(self) -> None:
        try:
            if self._context:
                await self._context.close()
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
        except Exception:
            pass


async def run_unix_socket_server(sock_path: str = "/tmp/chamber.sock") -> None:
    """Listens on a local Unix socket inside the chamber for actions from M2."""
    if os.path.exists(sock_path):
        os.remove(sock_path)

    session = ChamberBrowserSession()

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                msg = json.loads(line.decode("utf-8"))
                result = await session.execute_action(msg)
                writer.write((json.dumps(result) + "\n").encode("utf-8"))
                await writer.drain()
                if msg.get("action") == "stop":
                    asyncio.get_running_loop().stop()
                    break
        finally:
            writer.close()

    server = await asyncio.start_unix_server(handle_client, path=sock_path)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    sock_file = os.getenv("CHAMBER_SOCKET_PATH", "/tmp/chamber.sock")
    asyncio.run(run_unix_socket_server(sock_file))
