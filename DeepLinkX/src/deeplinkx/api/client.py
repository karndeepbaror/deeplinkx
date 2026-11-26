"""Tiny dependency-free Python client for the DEEPLINK X REST API."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from ..errors import DeeplinkXError


class ApiError(DeeplinkXError):
    def __init__(self, status: int, message: str):
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


class Client:
    def __init__(self, base_url: str = "http://127.0.0.1:8787", token: Optional[str] = None, timeout: float = 120):
        self.base = base_url.rstrip("/") + "/api/v1"
        self.token = token
        self.timeout = timeout

    def _req(self, method: str, path: str, body: Optional[bytes] = None, ctype: Optional[str] = None, raw: bool = False,
             **query: Any):
        q = {k: v for k, v in query.items() if v is not None}
        url = self.base + path + ("?" + urllib.parse.urlencode(q) if q else "")
        req = urllib.request.Request(url, data=body, method=method)
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        if ctype:
            req.add_header("Content-Type", ctype)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = resp.read()
        except urllib.error.HTTPError as exc:
            try:
                msg = json.loads(exc.read()).get("error", exc.reason)
            except Exception:
                msg = exc.reason
            raise ApiError(exc.code, str(msg)) from None
        except urllib.error.URLError as exc:
            raise DeeplinkXError(f"cannot reach {url}: {exc.reason}") from None
        return data if raw else json.loads(data)

    def health(self) -> dict:
        return self._req("GET", "/health")

    def info(self) -> dict:
        return self._req("GET", "/info")

    def submit(self, apk_path: str, profile: str = "standard", assetlinks: bool = False) -> dict:
        with open(apk_path, "rb") as fh:
            data = fh.read()
        name = apk_path.replace("\\", "/").rsplit("/", 1)[-1]
        return self._req("POST", "/scans", data, "application/octet-stream", profile=profile, filename=name,
                         assetlinks="1" if assetlinks else None)

    def wait(self, job_id: str, poll: float = 0.3, timeout: float = 600) -> dict:
        end = time.time() + timeout
        while time.time() < end:
            job = self._req("GET", f"/jobs/{job_id}")
            if job["state"] == "error":
                raise DeeplinkXError(job["error"])
            if job["state"] == "done":
                return job
            time.sleep(poll)
        raise DeeplinkXError("timed out waiting for the scan")

    def scan(self, apk_path: str, profile: str = "standard", **kw) -> dict:
        job = self.wait(self.submit(apk_path, profile, **kw)["id"])
        return self.get_scan(job["scan_id"])

    def scans(self, limit: int = 50, package: Optional[str] = None) -> list[dict]:
        return self._req("GET", "/scans", limit=limit, package=package)

    def get_scan(self, scan_id: int) -> dict:
        return self._req("GET", f"/scans/{scan_id}")

    def report(self, scan_id: int, fmt: str = "html") -> bytes:
        return self._req("GET", f"/scans/{scan_id}/report/{fmt}", raw=True)

    def graph(self, scan_id: int) -> dict:
        return self._req("GET", f"/scans/{scan_id}/graph")

    def diff(self, old: int, new: int) -> dict:
        return self._req("GET", f"/scans/{old}/diff/{new}")

    def delete_scan(self, scan_id: int) -> dict:
        return self._req("DELETE", f"/scans/{scan_id}")

    def set_status(self, package: str, finding: str, status: str, note: str = "") -> dict:
        return self._req("POST", "/findings/status",
                         json.dumps({"package": package, "finding": finding, "status": status, "note": note}).encode(),
                         "application/json")
