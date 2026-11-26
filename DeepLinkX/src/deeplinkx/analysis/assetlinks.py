from __future__ import annotations

import ipaddress
import json
import socket
import urllib.error
import urllib.request
from typing import Callable, Optional

from ..models import DeepLink

Fetcher = Callable[[str, float], tuple[int, bytes]]
HANDLE_ALL = "delegate_permission/common.handle_all_urls"
MAX_BYTES = 1_000_000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # Android does not follow redirects for assetlinks
        return None


def is_public_host(host: str) -> bool:
    """The host comes from an untrusted APK: refuse anything that resolves to a non public address."""
    if not host or host in ("localhost",) or host.endswith((".local", ".internal", ".localhost")):
        return False
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return True  # unresolved hosts are reported as unreachable by the fetch itself
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True


def default_fetcher(url: str, timeout: float) -> tuple[int, bytes]:
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "DeeplinkX-assetlinks-check"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read(MAX_BYTES)
    except urllib.error.HTTPError as exc:
        return exc.code, b""
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise ConnectionError(str(exc)) from exc


def _fp(sha256_hex: str) -> str:
    h = sha256_hex.upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def candidate_hosts(links: list[DeepLink]) -> list[str]:
    hosts: list[str] = []
    for l in links:
        if l.is_web and l.auto_verify and l.host:
            h = l.host[2:] if l.host.startswith("*.") else l.host
            if h not in hosts and "*" not in h:
                hosts.append(h)
    return hosts


def verify_hosts(hosts: list[str], package: str, cert_sha256: list[str], timeout: float = 6.0,
                 fetcher: Optional[Fetcher] = None) -> list[dict]:
    fetch = fetcher or default_fetcher
    want = {_fp(c) for c in cert_sha256}
    out = []
    for host in hosts:
        url = f"https://{host}/.well-known/assetlinks.json"
        row = {"host": host, "url": url, "status": "unreachable", "detail": ""}
        if fetcher is None and not is_public_host(host):
            row.update(status="skipped", detail="host resolves to a non public address")
            out.append(row)
            continue
        try:
            code, body = fetch(url, timeout)
        except ConnectionError as exc:
            row["detail"] = str(exc)[:200]
            out.append(row)
            continue
        if code in (301, 302, 303, 307, 308) or code is None:
            row.update(status="redirect", detail=f"HTTP {code}: Android does not follow redirects")
        elif code == 404:
            row.update(status="missing", detail="HTTP 404")
        elif code != 200:
            row.update(status="error", detail=f"HTTP {code}")
        else:
            try:
                data = json.loads(body.decode("utf-8", "replace"))
                if not isinstance(data, list):
                    raise ValueError("top level value is not a list")
            except ValueError as exc:
                row.update(status="invalid", detail=f"not valid assetlinks json: {exc}")
                out.append(row)
                continue
            pkg_seen = False
            matched = False
            for stmt in data:
                if not isinstance(stmt, dict):
                    continue
                target = stmt.get("target") or {}
                if target.get("namespace") != "android_app" or HANDLE_ALL not in (stmt.get("relation") or []):
                    continue
                if target.get("package_name") != package:
                    continue
                pkg_seen = True
                fps = {str(x).upper() for x in target.get("sha256_cert_fingerprints", [])}
                if fps & want:
                    matched = True
            if matched:
                row.update(status="verified", detail="package and certificate fingerprint match")
            elif pkg_seen:
                row.update(status="mismatch", detail="package listed but certificate fingerprint differs")
            else:
                row.update(status="not_listed", detail="package is not listed in assetlinks.json")
        out.append(row)
    return out
