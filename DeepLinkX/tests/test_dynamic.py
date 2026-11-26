import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from deeplinkx.analysis import analyze_apk
from deeplinkx.config import DynamicSettings
from deeplinkx.dynamic import (Adb, DynamicRunner, SafetyPolicy, confirm_static, findings_from_run, generate_cases)
from deeplinkx.dynamic.testcases import CANARY_HOST
from deeplinkx.errors import DynamicError, SafetyError
from deeplinkx.scan import run_scan

FAKE = Path(__file__).parent / "fixtures" / "fake_adb.py"


@pytest.fixture
def fake_env(tmp_path, monkeypatch):
    state = tmp_path / "adbstate"
    state.mkdir()
    wrapper = tmp_path / "adb"
    wrapper.write_text(f'#!/bin/sh\nexec {sys.executable} {FAKE} "$@"\n')
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("FAKE_ADB_DIR", str(state))
    return {"adb": str(wrapper), "state": state}


@pytest.fixture(scope="module")
def analysis(vuln_apk):
    return analyze_apk(vuln_apk)


def _runner(analysis, fake_env, vuln_apk, tmp_path, authorized=True, **kw):
    policy = SafetyPolicy(authorized=authorized, **kw.pop("policy", {}))
    adb = Adb(fake_env["adb"], policy=policy, timeout=5)
    settings = kw.pop("settings", DynamicSettings(settle_ms=0, command_timeout=5))
    return DynamicRunner(adb, analysis, policy, settings, apk_path=vuln_apk, out_dir=tmp_path / "ev", **kw)


# ---------------------------------------------------------------- test case generation
def test_case_generation(analysis):
    cases = generate_cases(analysis, DynamicSettings())
    assert len(cases) > 30
    assert len({c.id for c in cases}) == len(cases) and cases[0].id == "T001"
    cats = {c.category for c in cases}
    assert {"baseline", "canary", "redirect", "host-confusion", "scheme-injection", "traversal", "long-input",
            "special-chars", "empty", "component", "provider"} <= cats
    dl = [c for c in cases if c.kind == "deeplink"]
    assert all(c.component == "com.shop.demo.DeepLinkActivity" for c in dl)
    assert {"myshop://pay", "https://shop.example.com/product"} <= {c.uri.split("?")[0].split("/..")[0].rstrip("x").rstrip("/")
                                                                   if "product" not in c.uri else
                                                                   "https://shop.example.com/product" for c in dl}
    # redirect parameter names come from the code analysis ("redirect" is in the code strings)
    assert any("redirect=" in c.uri for c in dl)
    # non destructive: every external URL points at the unresolvable canary host
    for c in dl:
        for part in ("http://", "https://"):
            tail = c.uri.split("?", 1)[1] if "?" in c.uri else ""
            if "http" in tail:
                assert CANARY_HOST in tail or "example.com" in tail
    cmd = next(c for c in dl if c.name == "javascript-scheme").command
    assert cmd.startswith("adb shell am start -W -n com.shop.demo/com.shop.demo.DeepLinkActivity")
    assert "'" in cmd  # URIs are shell quoted
    prov = [c for c in cases if c.kind == "provider"]
    assert len(prov) == 3 and all("content://com.shop.demo.data/" in c.command for c in prov)
    admin = next(c for c in cases if c.component.endswith("AdminActivity"))
    assert admin.expect == "denied"


def test_case_limits_and_filters(analysis):
    few = generate_cases(analysis, DynamicSettings(max_cases_per_link=3, include_providers=False,
                                                   include_component_launch=False))
    per_link = {}
    for c in few:
        per_link[c.link] = per_link.get(c.link, 0) + 1
    assert set(per_link.values()) == {3}
    only = generate_cases(analysis, DynamicSettings(categories=["traversal"], include_providers=False,
                                                    include_component_launch=False))
    assert {c.category for c in only} == {"traversal"}


def test_plugin_generator(analysis):
    gen = lambda link, ctx: [{"category": "plugin", "name": "mine", "uri": "myshop://pay/plugin", "description": "d"}]
    cases = generate_cases(analysis, DynamicSettings(max_cases_per_link=40), generators=[gen])
    assert any(c.name == "mine" for c in cases)


# ---------------------------------------------------------------- safety rails
def test_authorization_is_mandatory(analysis, fake_env, vuln_apk, tmp_path):
    with pytest.raises(SafetyError, match="--authorized"):
        _runner(analysis, fake_env, vuln_apk, tmp_path, authorized=False).run()


def test_physical_device_refused_by_default(analysis, fake_env, vuln_apk, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_ADB_PHYSICAL", "1")
    monkeypatch.setenv("FAKE_ADB_DEVICES", "R5CT1234567\\tdevice usb:1-1 model:Pixel_7")
    with pytest.raises(SafetyError, match="emulator"):
        _runner(analysis, fake_env, vuln_apk, tmp_path).run()
    run = _runner(analysis, fake_env, vuln_apk, tmp_path, policy={"allow_physical": True},
                  settings=DynamicSettings(settle_ms=0, categories=["baseline"], include_providers=False,
                                           include_component_launch=False)).run()
    assert run.device["emulator"] is False and run.results


def test_policy_blocks_dangerous_commands():
    p = SafetyPolicy(package="com.shop.demo", authorized=True, authorities={"com.shop.demo.data"})
    ok = [["shell", "am", "start", "-W", "-n", "com.shop.demo/.A"],
          ["shell", "content", "query", "--uri", "content://com.shop.demo.data/x"],
          ["shell", "am", "force-stop", "com.shop.demo"], ["logcat", "-d"], ["exec-out", "screencap", "-p"]]
    for a in ok:
        p.check_adb(a)
    bad = [["shell", "rm", "-rf", "/sdcard"], ["shell", "am", "start", "-n", "com.other.app/.Main"],
           ["shell", "content", "query", "--uri", "content://com.android.contacts/contacts"],
           ["shell", "am", "start", "-n", "com.shop.demo/.A", ";", "reboot"], ["reboot"], ["root"],
           ["shell", "pm", "clear", "com.shop.demo"], ["shell", "su", "0", "id"], ["uninstall", "com.shop.demo"],
           ["shell", "settings", "put", "global", "x", "1"], ["exec-out", "cat", "/data/x"],
           ["shell", "am", "broadcast", "-a", "android.intent.action.BOOT_COMPLETED"],
           ["shell", "content", "insert", "--uri", "content://com.shop.demo.data/x"],
           ["shell", "dumpsys", "meminfo"], ["emu", "console"]]
    for a in bad:
        with pytest.raises(SafetyError):
            p.check_adb(a)
    with pytest.raises(SafetyError):
        p.check_serial("bad serial; rm")


def test_adb_never_runs_blocked_command(fake_env):
    policy = SafetyPolicy(package="com.shop.demo", authorized=True)
    adb = Adb(fake_env["adb"], policy=policy)
    with pytest.raises(SafetyError):
        adb.shell(["rm", "-rf", "/"])
    assert not (fake_env["state"] / "calls.txt").exists()


def test_not_installed_and_install_flow(analysis, fake_env, vuln_apk, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_ADB_NOT_INSTALLED", "1")
    with pytest.raises(DynamicError, match="not installed"):
        _runner(analysis, fake_env, vuln_apk, tmp_path).run()
    # --install adds the package (the fake keeps reporting it missing, so the check still fails afterwards)
    r = _runner(analysis, fake_env, vuln_apk, tmp_path, install=True)
    with pytest.raises(DynamicError, match="not installed"):
        r.run()
    assert "install" in (fake_env["state"] / "calls.txt").read_text()


# ---------------------------------------------------------------- end to end
@pytest.fixture
def run_result(analysis, fake_env, vuln_apk, tmp_path):
    runner = _runner(analysis, fake_env, vuln_apk, tmp_path)
    return runner.run(), runner


def test_dynamic_run_outcomes(run_result):
    run, _ = run_result
    by = {(r.case.component.rsplit(".", 1)[-1], r.case.name): r for r in run.results}
    assert run.device["serial"] == "emulator-5554" and run.device["emulator"]
    assert by[("DeepLinkActivity", "baseline")].observation.outcome == "launched"
    assert by[("DeepLinkActivity", "baseline")].observation.resolved.endswith("DeepLinkActivity")
    assert by[("DeepLinkActivity", "long-parameter")].observation.outcome == "crash"
    assert "java.lang.IllegalStateException" in by[("DeepLinkActivity", "long-parameter")].observation.exceptions
    assert by[("AdminActivity", "explicit-launch")].observation.outcome == "denied"
    assert by[("DeepLinkActivity", "param-redirect-canary-url")].observation.flags.count("canary_url_loaded") == 1
    assert "canary_url_loaded" not in by[("DeepLinkActivity", "javascript-scheme")].observation.flags
    assert by[("DataProvider", "provider-query")].observation.outcome == "data_returned"
    assert by[("DataProvider", "provider-sql-quote")].observation.outcome == "provider_error"
    assert "sql_error" in by[("DataProvider", "provider-sql-quote")].observation.flags
    assert run.counts()["launched"] > 10
    assert by[("DeepLinkActivity", "baseline")].screenshot.endswith(".png")


def test_dynamic_findings_and_confirmation(run_result, vuln_apk, tmp_path):
    run, _ = run_result
    dyn = findings_from_run(run)
    ids = {f.rule_id for f in dyn}
    assert {"DLX-501", "DLX-503", "DLX-504", "DLX-505", "DLX-506"} <= ids
    crash = next(f for f in dyn if f.rule_id == "DLX-501")
    assert crash.source == "dynamic" and crash.confidence.name == "CERTAIN"
    assert any(e.kind == "log" for e in crash.evidence) and crash.reproduction[0].startswith("adb shell am start")
    report = run_scan(vuln_apk, "standard", save=False)
    n = confirm_static(report.findings, run)
    assert n >= 3
    f = next(x for x in report.findings if x.rule_id == "DLX-101" and x.component.endswith("DebugActivity"))
    assert f.status.value == "confirmed" and f.confidence.name == "CERTAIN"
    assert any(e.kind == "dynamic" for e in f.evidence)


def test_evidence_directory_and_repro_script(run_result):
    run, runner = run_result
    ev = Path(run.evidence_dir)
    assert (ev / "run.json").is_file() and (ev / "transcript.log").is_file()
    assert len(list((ev / "logs").glob("*.log"))) == len(run.results)
    assert list((ev / "screens").glob("*.png"))
    script = ev / "repro.sh"
    assert os.access(script, os.X_OK)
    assert subprocess.run(["bash", "-n", str(script)]).returncode == 0
    text = script.read_text()
    assert "adb -s emulator-5554" in text and "logcat -c" in text and "T001" in text
    assert all(r.case.id in text for r in run.results)
    # reproducible: the same plan gives the same ordered cases and commands
    again = runner.plan()
    assert [c.id for c in again] == [r.case.id for r in run.results]
    assert [c.command for c in again] == [r.case.command for r in run.results]
    assert "FATAL EXCEPTION" in (ev / "logs" / next(r.case.id for r in run.results
                                                     if r.observation.outcome == "crash")).with_suffix(".log").read_text()


def test_unresponsive_device_stops_early(analysis, fake_env, vuln_apk, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_ADB_HANG", "1")
    runner = _runner(analysis, fake_env, vuln_apk, tmp_path,
                     settings=DynamicSettings(settle_ms=0, command_timeout=1, screenshots=False, categories=["baseline", "canary"],
                                              include_providers=False, include_component_launch=False))
    run = runner.run()
    assert len(run.results) == 3 and all(r.observation.outcome == "timeout" for r in run.results)
    assert any("unresponsive" in n for n in run.notes)
