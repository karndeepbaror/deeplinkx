"""REST API + dashboard host (Starlette).

Auth: set DEEPLINKX_API_TOKEN to require ``Authorization: Bearer <token>`` (or ``?token=`` for EventSource/downloads).
All /api/v1 routes except /health require it; the static dashboard shell is public and asks for the token itself.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Optional

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .. import version as V
from ..config import home_dir, list_profiles, load_profile
from ..errors import DeeplinkXError
from ..findings import HistoryError, Store
from ..reports import FORMATS, render
from ..rules import build_registry
from .graph import build_graph
from .jobs import JobManager

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
MIME = {"html": "text/html; charset=utf-8", "json": "application/json", "pdf": "application/pdf",
        "sarif": "application/sarif+json"}
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _err(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


class ApiState:
    def __init__(self) -> None:
        self.store = Store()
        self.jobs = JobManager(self.store)
        self.max_upload = int(os.environ.get("DEEPLINKX_MAX_UPLOAD_MB", "300")) * 1024 * 1024


def create_app(state: Optional[ApiState] = None) -> Starlette:
    st = state or ApiState()

    def token_ok(request: Request) -> bool:
        token = os.environ.get("DEEPLINKX_API_TOKEN")
        if not token:
            return True
        given = request.headers.get("authorization", "")
        given = given[7:] if given.lower().startswith("bearer ") else request.query_params.get("token", "")
        return hmac.compare_digest(given.encode(), token.encode())

    def guarded(fn):
        async def wrapper(request: Request):
            if not token_ok(request):
                return JSONResponse({"error": "unauthorized"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
            try:
                return await fn(request)
            except HistoryError as exc:
                return _err(404, str(exc))
            except DeeplinkXError as exc:
                return _err(400, str(exc))
            except ValueError as exc:
                return _err(400, str(exc))
        wrapper.__name__ = fn.__name__
        return wrapper

    def scan_id(request: Request, key: str = "id") -> int:
        try:
            return int(request.path_params[key])
        except ValueError:
            raise ValueError("scan id must be an integer")

    async def health(request: Request):
        return JSONResponse({"status": "ok", "version": V.__version__, "auth": bool(os.environ.get("DEEPLINKX_API_TOKEN"))})

    async def info(request: Request):
        return JSONResponse({"tool": V.TOOL_NAME, "version": V.__version__, "tagline": V.TAGLINE,
                             "profiles": list_profiles(), "formats": list(FORMATS), "home": str(home_dir()),
                             "max_upload_mb": st.max_upload // (1024 * 1024)})

    async def profiles(request: Request):
        return JSONResponse([load_profile(n).to_dict() | {"name": n} for n in list_profiles()])

    async def rules(request: Request):
        reg = build_registry(load_profile(None))
        return JSONResponse([{"id": r.meta.id, "title": r.meta.title, "severity": r.meta.severity.name,
                              "category": r.meta.category, "confidence": r.meta.confidence.name,
                              "description": r.meta.description, "remediation": r.meta.remediation,
                              "source": r.meta.source} for r in reg.rules])

    async def create_scan(request: Request):
        profile = request.query_params.get("profile", "standard")
        if profile not in list_profiles():
            return _err(400, f"unknown profile '{profile}'")
        name = SAFE_NAME.sub("_", request.query_params.get("filename", "upload.apk"))[:120] or "upload.apk"
        updir = home_dir() / "uploads"
        updir.mkdir(parents=True, exist_ok=True)
        fd, path = tempfile.mkstemp(suffix=".apk", dir=updir)
        size = 0
        try:
            with os.fdopen(fd, "wb") as fh:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > st.max_upload:
                        raise ValueError(f"upload larger than {st.max_upload // (1024 * 1024)} MB")
                    fh.write(chunk)
            with open(path, "rb") as fh:
                if fh.read(4) != b"PK\x03\x04":
                    raise ValueError("not an APK/ZIP file")
        except Exception as exc:
            os.unlink(path)
            return _err(413 if "larger" in str(exc) else 400, str(exc))
        job = st.jobs.submit(path, name, profile, {"assetlinks": request.query_params.get("assetlinks") == "1"})
        return JSONResponse(job.to_dict(), status_code=202)

    async def get_job(request: Request):
        job = st.jobs.jobs.get(request.path_params["job"])
        if not job:
            return _err(404, "unknown job")
        return JSONResponse(job.to_dict())

    async def job_events(request: Request):
        from sse_starlette.sse import EventSourceResponse

        job = st.jobs.jobs.get(request.path_params["job"])
        if not job:
            return _err(404, "unknown job")

        async def gen():
            i = 0
            while True:
                while i < len(job.events):
                    yield {"event": "progress", "data": json.dumps(job.events[i])}
                    i += 1
                if job.state in ("done", "error") and i >= len(job.events):
                    yield {"event": "end", "data": json.dumps(job.to_dict())}
                    return
                if await request.is_disconnected():
                    return
                await asyncio.sleep(0.15)

        return EventSourceResponse(gen())

    async def list_scans(request: Request):
        limit = min(int(request.query_params.get("limit", "50")), 500)
        return JSONResponse(st.store.list_scans(limit, request.query_params.get("package")))

    def overlay(rep: dict) -> dict:
        known = st.store.statuses(rep["apk"]["package"])
        for f in rep["findings"]:
            if f["fingerprint"] in known:
                f["status"] = known[f["fingerprint"]]["status"]
        return rep

    async def get_scan(request: Request):
        return JSONResponse(overlay(st.store.get_scan(scan_id(request))))

    async def delete_scan(request: Request):
        if not st.store.delete_scan(scan_id(request)):
            return _err(404, "scan not found")
        return JSONResponse({"deleted": True})

    async def scan_report(request: Request):
        fmt = request.path_params["fmt"].lower()
        if fmt not in FORMATS:
            return _err(400, f"unknown format '{fmt}'")
        sid = scan_id(request)
        rep = overlay(st.store.get_scan(sid))
        body = await asyncio.to_thread(render, rep, fmt)
        headers = {"Content-Disposition": f'attachment; filename="deeplinkx-scan-{sid}.{fmt}"'} \
            if request.query_params.get("download") else {}
        if fmt == "html":  # reports are self-contained; lock them down when viewed inline
            headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
        return Response(body, media_type=MIME[fmt], headers=headers)

    async def scan_graph(request: Request):
        return JSONResponse(build_graph(overlay(st.store.get_scan(scan_id(request)))))

    async def scan_diff(request: Request):
        a = st.store.get_scan(scan_id(request))
        b = st.store.get_scan(scan_id(request, "other"))
        return JSONResponse(st.store.diff(a, b))

    async def set_status(request: Request):
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return _err(400, "invalid JSON body")
        for k in ("package", "finding", "status"):
            if not isinstance(body.get(k), str):
                return _err(400, f"'{k}' is required")
        fps = st.store.set_status(body["package"], body["finding"], body["status"], str(body.get("note", ""))[:500])
        return JSONResponse({"updated": fps, "status": body["status"]})

    async def package_trend(request: Request):
        rows = st.store.list_scans(200, request.path_params["package"])
        return JSONResponse([{"id": r["id"], "created": r["created"], "risk": r["risk"], "counts": r["counts"]}
                             for r in reversed(rows)])

    v1 = "/api/v1"
    routes = [
        Route(f"{v1}/health", health),
        Route(f"{v1}", guarded(info)),
        Route(f"{v1}/info", guarded(info)),
        Route(f"{v1}/profiles", guarded(profiles)),
        Route(f"{v1}/rules", guarded(rules)),
        Route(f"{v1}/scans", guarded(create_scan), methods=["POST"]),
        Route(f"{v1}/scans", guarded(list_scans), methods=["GET"]),
        Route(f"{v1}/jobs/{{job}}", guarded(get_job)),
        Route(f"{v1}/jobs/{{job}}/events", guarded(job_events)),
        Route(f"{v1}/scans/{{id}}", guarded(get_scan), methods=["GET"]),
        Route(f"{v1}/scans/{{id}}", guarded(delete_scan), methods=["DELETE"]),
        Route(f"{v1}/scans/{{id}}/report/{{fmt}}", guarded(scan_report)),
        Route(f"{v1}/scans/{{id}}/graph", guarded(scan_graph)),
        Route(f"{v1}/scans/{{id}}/diff/{{other}}", guarded(scan_diff)),
        Route(f"{v1}/findings/status", guarded(set_status), methods=["POST"]),
        Route(f"{v1}/packages/{{package}}/trend", guarded(package_trend)),
    ]
    if WEB_DIR.is_dir():
        routes.append(Mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web"))

    class Headers:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            async def wrap(msg):
                if msg["type"] == "http.response.start":
                    h = dict(msg.get("headers") or [])
                    extra = [(b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"no-referrer"),
                             (b"x-frame-options", b"DENY")]
                    msg["headers"] = list(msg.get("headers") or []) + [e for e in extra if e[0] not in h]
                await send(msg)
            await self.app(scope, receive, wrap)

    app = Starlette(routes=routes, middleware=[Middleware(Headers)])
    app.state.dlx = st
    return app


def run_server(host: str = "127.0.0.1", port: int = 8787) -> None:
    import uvicorn

    uvicorn.run(create_app(), host=host, port=port, log_level="warning")
