"""
BaitBox — Shared Egress Filter & Download Quarantine Engine (backend/app/egress_rules.py)
=========================================================================================
Provides deterministic IP/hostname egress inspection and executable/archive
download quarantine logic with SHA-256 hashing. Used both by M6 Egress Filter
and the local sandbox worker so that containment behavior is 100% identical in
Docker/gVisor and local development modes.
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

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
    "100.100.100.200",
}


def check_outbound_url_allowed(
    url: str,
    control_plane_host: str = "",
    allow_local_trap_path: bool = True,
) -> Tuple[bool, str]:
    """
    Checks whether a URL is allowed to exit the disposable chamber through M6.
    Blocks:
    - Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
    - Private RFC1918 networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - Loopback / control plane addresses (except explicit `/trap/` demo paths when local)
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Malformed URL rejected by M6 Egress Filter"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, f"Disallowed scheme '{scheme}://' blocked by M6 Egress Filter"

    host = (parsed.hostname or "").strip().lower()
    path = parsed.path or "/"

    if not host:
        return False, "Empty hostname blocked by M6 Egress Filter"

    # 1. Always block cloud metadata addresses
    if host in METADATA_HOSTS or host.startswith("169.254."):
        return (
            False,
            f"Cloud instance metadata endpoint ({host}) refused by M6 Egress Filter (SSRF protection)",
        )

    # Allow built-in `/trap/` mock phishing routes hosted on local test server
    if allow_local_trap_path and host in ("localhost", "127.0.0.1", "0.0.0.0", "testserver") and path.startswith("/trap/"):
        return True, "Allowed built-in mock phishing test trap"

    # 2. Block control plane address itself
    if control_plane_host and host == control_plane_host.lower():
        return (
            False,
            f"Control plane host ({host}) refused by M6 Egress Filter",
        )

    # 3. Check IP literal ranges
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_link_local or str(ip) == "169.254.169.254":
            return False, f"Link-local / cloud metadata address ({ip}) refused by M6 Egress Filter"
        if ip.is_loopback or ip.is_private or ip.is_reserved or ip.is_multicast:
            return False, f"Private/internal IP range ({ip}) refused by M6 Egress Filter"
        return True, "Public IP allowed"
    except ValueError:
        pass

    # 4. Block internal hostnames
    if host in ("localhost", "internal", "control-plane", "orchestrator") or host.endswith(".internal") or host.endswith(".local"):
        return False, f"Internal hostname ({host}) refused by M6 Egress Filter"

    return True, "Public hostname allowed"


def inspect_response_for_quarantine(
    url: str,
    headers: Dict[str, str],
    body: bytes,
) -> Optional[Dict[str, Any]]:
    """
    Inspects an HTTP response for executable/archive downloads or EICAR test
    files. If matched, returns a quarantine record with the exact SHA-256 hash.
    """
    parsed = urlparse(url)
    path_lower = (parsed.path or "").lower()
    headers_lower = {k.lower(): v for k, v in (headers or {}).items()}
    content_type = headers_lower.get("content-type", "").split(";")[0].strip().lower()
    content_disp = headers_lower.get("content-disposition", "")
    content_disp_lower = content_disp.lower()

    filename = Path(parsed.path).name or "download.bin"
    if "filename=" in content_disp_lower:
        idx = content_disp_lower.find("filename=")
        filename = content_disp[idx + 9 :].strip(' "\';')

    filename_lower = filename.lower()
    matched_ext = next(
        (ext for ext in BLOCKED_EXTENSIONS if filename_lower.endswith(ext) or path_lower.endswith(ext)),
        None,
    )
    is_blocked_mime = content_type in BLOCKED_MIME_TYPES
    is_eicar = EICAR_SIGNATURE in (body or b"")

    if matched_ext or is_blocked_mime or is_eicar:
        sha256_hex = hashlib.sha256(body or b"").hexdigest()
        reason_parts = [f"Executable/archive download '{filename}' intercepted and quarantined by M6 Egress Filter"]
        if is_eicar:
            reason_parts.append("EICAR antivirus test signature detected")
        reason_parts.append(f"SHA-256: {sha256_hex}")
        return {
            "filename": filename,
            "url": url,
            "content_type": content_type or "application/octet-stream",
            "size_bytes": len(body or b""),
            "sha256": sha256_hex,
            "is_eicar": is_eicar,
            "quarantined_by": "M6 Egress Filter",
            "reason": " — ".join(reason_parts),
        }

    return None
