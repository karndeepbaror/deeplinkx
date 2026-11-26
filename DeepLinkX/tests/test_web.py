"""Browser tests of the dashboard (Playwright + the bundled Chromium). Skipped when Playwright is unavailable."""
import socket
import threading
import time

import pytest
import uvicorn

pw = pytest.importorskip("playwright.sync_api")

from deeplinkx.api import create_app  # noqa: E402


@pytest.fixture()
def url():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    srv = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=srv.run, daemon=True); t.start()
    while not srv.started:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True; t.join(5)


@pytest.fixture()
def page():
    with pw.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:  # pragma: no cover
            pytest.skip(f"chromium unavailable: {exc}")
        pg = b.new_page(viewport={"width": 1280, "height": 900})
        errors = []
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        pg.errors = errors
        yield pg
        b.close()


def test_dashboard_end_to_end(url, page, vuln_apk, tmp_path):
    page.goto(url)
    page.wait_for_selector(".drop")
    page.set_input_files("input[type=file]", str(vuln_apk))
    page.wait_for_url("**/#/scan/1", timeout=30000)
    page.wait_for_selector(".gauge")
    assert "com.shop.demo" in page.inner_text("h1")
    # findings tab: filter, expand, change status
    page.click("text=Findings")
    page.wait_for_selector(".finding")
    n_all = page.locator(".finding").count()
    page.select_option("select >> nth=0", "HIGH")
    assert 0 < page.locator(".finding").count() <= n_all
    page.locator(".finding .f-head").first.click()
    assert page.locator(".finding.open .f-body").first.is_visible()
    page.locator(".finding.open select").first.select_option("false_positive")
    page.wait_for_selector(".toast")
    # deep links + entry points
    page.click("text=Deep links"); page.wait_for_selector("text=myshop://pay")
    page.click("text=Entry points"); page.wait_for_selector("text=DebugActivity")
    # graph renders pixels
    page.click("role=tab[name=/Graph/]"); page.wait_for_selector("#graphwrap canvas")
    page.wait_for_timeout(1200)
    painted = page.evaluate("""() => { const c=document.querySelector('canvas'); const d=c.getContext('2d').getImageData(0,0,c.width,c.height).data; let n=0; for(let i=3;i<d.length;i+=4) if(d[i]) n++; return n; }""")
    assert painted > 2000
    page.mouse.move(640, 450); page.mouse.wheel(0, -200)
    page.click("text=Permissions"); page.wait_for_selector("text=SEND_SMS")
    page.click("text=Dynamic"); page.wait_for_selector("text=No dynamic run")
    # history + rules + theme
    page.goto(url + "/#/scans"); page.wait_for_selector("text=com.shop.demo")
    page.goto(url + "/#/rules"); page.wait_for_selector("text=DLX-211")
    page.click("#theme")
    assert page.evaluate("document.documentElement.dataset.theme") == "light"
    page.screenshot(path=str(tmp_path / "rules.png"))
    assert page.errors == []


def test_xss_is_inert(url, page, tmp_path):
    from fixtures.builders import build_apk, manifest_tree, activity, intent_filter, VIEW, DEFAULT, BROWSABLE
    evil = '"><img src=x onerror=window.__pwned=1>'
    tree = manifest_tree("com.evil.app", components=[activity(".A", [intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "x" + "evil", "host": "<script>window.__pwned=1</script>"}])], exported=True)])
    apk = build_apk(tmp_path / "e.apk", tree)
    page.goto(url); page.wait_for_selector(".drop")
    page.set_input_files("input[type=file]", str(apk))
    page.wait_for_url("**/#/scan/1", timeout=30000)
    page.click("text=Deep links"); page.wait_for_selector("table")
    assert page.evaluate("window.__pwned") is None
