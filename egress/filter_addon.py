#!/usr/bin/env python3
"""
BaitBox — M6 Egress Filter (egress/filter_addon.py)
===================================================
mitmproxy add-on that serves as the disposable chamber's ONLY route to the internet.

Core containment rules enforced:
1. Allows ordinary web traffic (HTTP and HTTPS) to public addresses.
2. Blocks private/internal IPv4 & IPv6 ranges (RFC 1918, loopback, link-local),
   the cloud instance metadata endpoint (`169.254.169.254`), and the control
   plane address itself.
3. Blocks and quarantines downloads of executable and archive file types
   (`.exe`, `.msi`, `.apk`, `.bat`, `.ps1`, `.scr`, `.zip`, `.rar`) as well as
   EICAR antivirus test payloads, recording the SHA-256 hash of anything blocked.
4. Logs every blocked request or quarantined file as structured JSON so the
   orchestrator (M2) and evidence store (M8) include it in the Containment Report.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import time
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from mitmproxy import http  # type: ignore

BLOCKED_EXTENSIONS = {
    ".exe",
    ".msi",
    ".apk",
    ".bat",
    ".cmd",
    ".ps1",
    ".scr",
    ".vbs",
    ".dll",
    ".zip",
    ".rar",
    ".7z",
    ".iso",
}

BLOCKED_MIME_TYPES = {
    "application/x-msdownload",
    "application/x-dosexec",
    "application/x-executable",
    "application/x-msi",
    "application/vnd.android.package-archive",
    "application/zip",
    "application/x-zip-compressed",
    "application/x-rar-compressed",
}

EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

METADATA_HOSTS = {
    "169.254.169.254",
    "169.254.170.2",
    "metadata.google.internal",
    "metadata",
}


class BaitBoxEgressFilter:
    def __init__(self) -> None:
        self.control_plane_host = os.getenv("CONTROL_PLANE_ADDRESS", "").strip().lower()
        self.log_path = Path(os.getenv("EGRESS_LOG_PATH", "/tmp/egress_blocks.jsonl"))
        self.events: List[Dict[str, Any]] = []

    def _record_block(self, event: Dict[str, Any]) -> None:
        event["timestamp"] = time.time()
        self.events.append(event)
        line = json.dumps(event)
        print(f"BAITBOX_EGRESS_BLOCK: {line}", flush=True)
        try:
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except Exception:
            pass

    def _is_blocked_ip(self, host: str) -> tuple[bool, str]:
        host_clean = host.strip().lower()
        if host_clean in METADATA_HOSTS:
            return True, "Cloud metadata address (169.254.169.254) blocked by M6 Egress Filter"
        if self.control_plane_host and host_clean == self.control_plane_host:
            return True, f"Control plane address ({self.control_plane_host}) blocked by M6 Egress Filter"

        try:
            ip = ipaddress.ip_address(host_clean)
            if ip.is_link_local or str(ip) == "169.254.169.254":
                return True, f"Link-local / metadata IP ({ip}) blocked by M6 Egress Filter"
            if ip.is_loopback or ip.is_private or ip.is_reserved or ip.is_multicast:
                return True, f"Private/internal IP range ({ip}) blocked by M6 Egress Filter"
        except ValueError:
            # Resolve hostname to verify no DNS rebinding to private/metadata IPs
            try:
                for res in socket.getaddrinfo(host_clean, None):
                    resolved_ip = ipaddress.ip_address(res[4][0])
                    if resolved_ip.is_link_local or str(resolved_ip) == "169.254.169.254":
                        return True, f"Host {host_clean} resolved to metadata IP ({resolved_ip})"
                    if resolved_ip.is_loopback or resolved_ip.is_private:
                        return True, f"Host {host_clean} resolved to internal IP ({resolved_ip})"
            except Exception:
                pass
        return False, ""

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        url = flow.request.pretty_url

        # Special local endpoint so orchestrator can fetch all logged containment events
        if host == "egress.baitbox.internal" and flow.request.path == "/events":
            flow.response = http.Response.make(
                200,
                json.dumps({"events": self.events}).encode("utf-8"),
                {"Content-Type": "application/json"},
            )
            return

        blocked, reason = self._is_blocked_ip(host)
        if blocked:
            self._record_block(
                {
                    "event_type": "egress_request_blocked",
                    "url": url,
                    "host": host,
                    "method": flow.request.method,
                    "reason": reason,
                }
            )
            flow.response = http.Response.make(
                403,
                json.dumps({"blocked_by": "BaitBox M6 Egress Filter", "reason": reason}).encode("utf-8"),
                {"Content-Type": "application/json"},
            )

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        url = flow.request.pretty_url
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        content_type = flow.response.headers.get("content-type", "").split(";")[0].strip().lower()
        content_disp = flow.response.headers.get("content-disposition", "").lower()
        raw_body = flow.response.raw_content or b""

        matched_ext = next((ext for ext in BLOCKED_EXTENSIONS if path_lower.endswith(ext) or ext in content_disp), None)
        is_blocked_mime = content_type in BLOCKED_MIME_TYPES
        is_eicar = EICAR_SIGNATURE in raw_body

        if matched_ext or is_blocked_mime or is_eicar:
            sha256_hex = hashlib.sha256(raw_body).hexdigest()
            filename = Path(parsed.path).name or "quarantined_payload.bin"
            if "filename=" in content_disp:
                filename = content_disp.split("filename=")[-1].strip(' "\'')

            reason = (
                f"Quarantined executable/archive download ({filename}, "
                f"{'EICAR test signature detected, ' if is_eicar else ''}"
                f"SHA-256: {sha256_hex[:16]}...)"
            )
            self._record_block(
                {
                    "event_type": "download_quarantined",
                    "url": url,
                    "filename": filename,
                    "content_type": content_type or "application/octet-stream",
                    "size_bytes": len(raw_body),
                    "sha256": sha256_hex,
                    "is_eicar": is_eicar,
                    "reason": reason,
                }
            )
            flow.response = http.Response.make(
                403,
                json.dumps(
                    {
                        "quarantined_by": "BaitBox M6 Egress Filter",
                        "filename": filename,
                        "sha256": sha256_hex,
                        "reason": reason,
                    }
                ).encode("utf-8"),
                {"Content-Type": "application/json"},
            )


addons = [BaitBoxEgressFilter()]
