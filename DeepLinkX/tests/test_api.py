import json
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest
import uvicorn

from deeplinkx.api import create_app
from deeplinkx.api.client import ApiError, Client
from deeplinkx.api.graph import build_graph


@pytest.fixture()
def server(tmp_path):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    srv = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    t.join(5)


def test_full_flow(server, vuln_apk):
    c = Client(server)
    assert c.health()["status"] == "ok"
    rep = c.scan(str(vuln_apk))
    assert rep["apk"]["package"] == "com.shop.demo" and rep["summary"]["total"] > 10
    sid = rep["meta"]["scan_id"] or c.scans()[0]["id"]
    assert c.scans(package="com.shop.demo")[0]["id"] == sid
    g = c.graph(sid)
    assert g["nodes"][0]["id"] == "app" and any(n["type"] == "deeplink" for n in g["nodes"])
    ids = {n["id"] for n in g["nodes"]}
    assert all(e["from"] in ids and e["to"] in ids for e in g["edges"])
    assert c.report(sid, "json").startswith(b"{")
    assert c.report(sid, "pdf").startswith(b"%PDF")
    assert b"<html" in c.report(sid, "html").lower()
    first = rep["findings"][0]
    assert c.set_status("com.shop.demo", first["id"], "false_positive")["status"] == "false_positive"
    assert next(f for f in c.get_scan(sid)["findings"] if f["id"] == first["id"])["status"] == "false_positive"
    c.scan(str(vuln_apk))
    d = c.diff(sid, c.scans()[0]["id"])
    assert "new" in d and "resolved" in d
    assert c.delete_scan(sid)["deleted"]
    with pytest.raises(ApiError) as e:
        c.get_scan(sid)
    assert e.value.status == 404


def test_validation_errors(server, tmp_path):
    c = Client(server)
    junk = tmp_path / "j.apk"
    junk.write_bytes(b"not a zip")
    with pytest.raises(ApiError) as e:
        c.submit(str(junk))
    assert e.value.status == 400
    with pytest.raises(ApiError):
        c.submit(str(junk), profile="nope")
    with pytest.raises(ApiError) as e:
        c._req("GET", "/scans/abc")
    assert e.value.status == 400
    with pytest.raises(ApiError):
        c.report(1, "exe")
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"PK\x03\x04" + b"0" * 50)
    with pytest.raises(Exception, match="not a valid|archive|zip|APK|manifest|ZIP"):
        c.scan(str(bad))


def test_token_auth(server, monkeypatch, vuln_apk):
    monkeypatch.setenv("DEEPLINKX_API_TOKEN", "s3cret")
    assert Client(server).health()["auth"] is True
    with pytest.raises(ApiError) as e:
        Client(server).scans()
    assert e.value.status == 401
    with pytest.raises(ApiError):
        Client(server, "wrong").scans()
    assert Client(server, "s3cret").scans() == []
    with urllib.request.urlopen(server + "/api/v1/scans?token=s3cret") as r:
        assert r.status == 200


def test_sse_progress_and_static(server, vuln_apk):
    c = Client(server)
    job = c.submit(str(vuln_apk))
    events, end = [], None
    with urllib.request.urlopen(f"{server}/api/v1/jobs/{job['id']}/events", timeout=60) as r:
        name = None
        for raw in r:
            line = raw.decode().strip()
            if line.startswith("event:"):
                name = line[6:].strip()
            elif line.startswith("data:"):
                (events if name == "progress" else [] ).append(json.loads(line[5:]))
                if name == "end":
                    end = json.loads(line[5:])
                    break
    assert end and end["state"] == "done" and len(events) >= 3
    with urllib.request.urlopen(server + "/") as r:
        assert b"DEEPLINK" in r.read()
        assert r.headers["x-content-type-options"] == "nosniff"


def test_upload_limit(tmp_path):
    from deeplinkx.api.server import ApiState

    state = ApiState()
    state.max_upload = 1000
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    srv = uvicorn.Server(uvicorn.Config(create_app(state), host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=srv.run, daemon=True); t.start()
    while not srv.started:
        time.sleep(0.05)
    try:
        big = tmp_path / "big.apk"
        big.write_bytes(b"PK\x03\x04" + b"0" * 5000)
        with pytest.raises(ApiError) as e:
            Client(f"http://127.0.0.1:{port}").submit(str(big))
        assert e.value.status == 413
    finally:
        srv.should_exit = True
        t.join(5)


def test_graph_hides_false_positive_counts(vuln_apk):
    from deeplinkx.scan import run_scan

    rep = run_scan(str(vuln_apk), "standard", save=False).to_dict()
    n = next(n for n in build_graph(rep)["nodes"] if n["meta"].get("findings"))
    for f in rep["findings"]:
        f["status"] = "false_positive"
    assert all(n["severity"] is None for n in build_graph(rep)["nodes"])
