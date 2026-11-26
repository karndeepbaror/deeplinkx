import json
import re

import pytest

from deeplinkx.reports import render, write_reports
from deeplinkx.scan import run_scan


@pytest.fixture(scope="module")
def report(vuln_apk, tmp_path_factory):
    from deeplinkx.findings import Store

    store = Store(tmp_path_factory.mktemp("h") / "h.db")
    run_scan(vuln_apk, "standard", store=store)
    return run_scan(vuln_apk, "standard", store=store).to_dict()  # second scan => diff section


def test_json_report(report):
    doc = json.loads(render(report, "json"))
    assert doc["schema_version"] == "1.0"
    assert doc["apk"]["package"] == "com.shop.demo"
    assert {"findings", "deep_links", "entry_points", "summary", "network_security"} <= set(doc)
    f = doc["findings"][0]
    assert {"id", "fingerprint", "severity", "confidence", "evidence", "reproduction", "remediation"} <= set(f)
    assert doc["diff"]["new"] == []


def test_html_report(report):
    html = render(report, "html").decode()
    assert html.startswith("<!doctype html>")
    assert "DEEPLINK" in html and "Every Link Has an Entry Point. Secure Every Entry." in html
    assert "com.shop.demo" in html and "myshop://pay" in html
    for f in report["findings"]:
        assert f["rule_id"] in html
    assert html.count('<details class="f"') == len(report["findings"])
    assert "github.com/karndeepbaror" in html and "x.com/karndeepbaror" in html
    assert "Since last scan" in html
    # no unresolved template syntax and everything user supplied is escaped
    assert "{{" not in html and "{%" not in html
    assert not re.search(r"<script[^>]*>[^<]*com\.shop", html)


def test_html_escapes_hostile_content(report):
    evil = json.loads(json.dumps(report))
    evil["findings"][0]["title"] = "<img src=x onerror=alert(1)>"
    evil["findings"][0]["evidence"][0]["content"] = "</pre><script>alert(1)</script>"
    html = render(evil, "html").decode()
    assert "<img src=x" not in html and "<script>alert(1)" not in html
    assert "&lt;img src=x" in html


def test_pdf_report(report):
    pdf = render(report, "pdf")
    assert pdf.startswith(b"%PDF-") and len(pdf) > 8000
    assert pdf.rstrip().endswith(b"%%EOF")
    import re as _re

    pages = len(_re.findall(rb"/Type\s*/Page[^s]", pdf))
    assert pages >= 5


def test_sarif_report(report):
    doc = json.loads(render(report, "sarif"))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "DEEPLINK X"
    assert len(run["results"]) == len(report["findings"])
    assert {r["ruleId"] for r in run["results"]} == {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(r["level"] in ("error", "warning", "note") for r in run["results"])


def test_write_reports_and_unknown_format(report, tmp_path):
    paths = write_reports(report, tmp_path / "out", ["html", "json", "pdf", "sarif"])
    assert [p.suffix for p in paths] == [".html", ".json", ".pdf", ".sarif"]
    assert all(p.stat().st_size > 500 for p in paths)
    with pytest.raises(Exception):
        write_reports(report, tmp_path, ["docx"])


def test_report_with_dynamic_section(vuln_apk, tmp_path, monkeypatch):
    # dynamic data is merged through attach_dynamic and rendered in all formats
    import stat
    import sys
    from pathlib import Path

    from deeplinkx.config import DynamicSettings
    from deeplinkx.dynamic import Adb, DynamicRunner, SafetyPolicy
    from deeplinkx.scan import attach_dynamic

    fake = Path(__file__).parent / "fixtures" / "fake_adb.py"
    state = tmp_path / "st"
    state.mkdir()
    wrapper = tmp_path / "adb"
    wrapper.write_text(f'#!/bin/sh\nexec {sys.executable} {fake} "$@"\n')
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("FAKE_ADB_DIR", str(state))
    rep = run_scan(vuln_apk, "standard", save=False)
    policy = SafetyPolicy(authorized=True)
    runner = DynamicRunner(Adb(str(wrapper), policy=policy, timeout=5), rep.analysis, policy,
                           DynamicSettings(settle_ms=0), out_dir=tmp_path / "ev")
    attach_dynamic(rep, runner.run())
    d = rep.to_dict()
    assert d["dynamic"]["confirmed_static"] >= 3 and d["dynamic"]["new_findings"] >= 4
    assert any(f["source"] == "dynamic" for f in d["findings"])
    html = render(d, "html").decode()
    assert 'id="dynamic"' in html and "T001" in html
    assert render(d, "pdf").startswith(b"%PDF")
