import textwrap

import pytest

from deeplinkx.config import Profile, load_profile
from deeplinkx.errors import RuleError
from deeplinkx.findings import Store, dedupe, finalize, summarize
from deeplinkx.models import Confidence, Finding, Severity, Status
from deeplinkx.rules import build_registry
from deeplinkx.rules.yaml_rules import load_yaml_rules
from deeplinkx.scan import run_scan
from fixtures.builders import LAUNCHER, MAIN, activity, build_apk, intent_filter, manifest_tree


@pytest.fixture(scope="module")
def report(vuln_apk, tmp_path_factory):
    store = Store(tmp_path_factory.mktemp("h") / "h.db")
    return run_scan(vuln_apk, "standard", store=store)


def ids(report, comp=None):
    return {f.rule_id for f in report.findings if comp is None or (f.component or "").endswith(comp)}


def test_registry_has_many_unique_rules():
    reg = build_registry(load_user_dirs=False)
    assert len(reg.rule_ids()) >= 50
    assert len(set(reg.rule_ids())) == len(reg.rule_ids())
    cats = {r.meta.category for r in reg.rules}
    assert {"Exposure", "Deep Link", "Input Handling", "WebView", "Signing", "Configuration", "Secrets"} <= cats


def test_findings_for_vulnerable_app(report):
    got = ids(report)
    expected = {"DLX-101", "DLX-103", "DLX-104", "DLX-105", "DLX-107", "DLX-108", "DLX-109",
                "DLX-201", "DLX-304", "DLX-301", "DLX-302", "DLX-306", "DLX-307", "DLX-308", "DLX-309",
                "DLX-314", "DLX-315", "DLX-402", "DLX-404", "DLX-405", "DLX-406", "DLX-407", "DLX-408",
                "DLX-413", "DLX-414", "DLX-415"}
    missing = expected - got
    assert not missing, missing


def test_component_specific_findings(report):
    assert {"DLX-301", "DLX-302", "DLX-304", "DLX-201"} <= ids(report, "DeepLinkActivity")
    assert "DLX-107" in ids(report, "InternalAlias")
    assert "DLX-308" in ids(report, "DebugActivity")
    # protected with a signature permission -> no exposure finding
    assert not ids(report, "AdminActivity")
    # weak custom permission is reported on the service, not as "no protection"
    svc = ids(report, "SyncService")
    assert "DLX-109" in svc and "DLX-102" not in svc


def test_severity_confidence_and_evidence(report):
    f = next(x for x in report.findings if x.rule_id == "DLX-308")
    assert f.severity == Severity.HIGH  # not same-method with input -> not escalated to critical
    assert f.status == Status.OPEN and f.id.startswith("F-")
    assert f.evidence and f.reproduction and f.remediation
    wv = next(x for x in report.findings if x.rule_id == "DLX-301" and x.component.endswith("WebViewActivity"))
    assert wv.confidence == Confidence.FIRM  # extra read and loadUrl in the same method
    kinds = {e.kind for e in wv.evidence}
    assert {"manifest", "code"} <= kinds
    assert any("adb shell am start" in r for r in wv.reproduction)
    dl = next(x for x in report.findings if x.rule_id == "DLX-301" and x.component.endswith("DeepLinkActivity"))
    assert any("-d" in r and "myshop://" in r or "https://shop.example.com" in r for r in dl.reproduction)


def test_findings_are_sorted_and_summarised(report):
    sev = [int(f.severity) for f in report.findings]
    assert sev == sorted(sev, reverse=True)
    s = report.summary
    assert s["active"] == len(report.findings) and s["risk_score"] > 50
    assert s["risk_level"] == "High" and s["by_severity"]["HIGH"] > 0
    assert report.rule_errors == []


def test_dedupe_merges_same_fingerprint():
    def mk(sev, aff):
        return Finding(rule_id="X-1", title="t", severity=sev, confidence=Confidence.FIRM, category="c",
                       description="d", remediation="r", component="a.B", key="k", affected=[aff])

    out = dedupe([mk(Severity.LOW, "a"), mk(Severity.HIGH, "b")])
    assert len(out) == 1 and out[0].occurrences == 2 and out[0].severity == Severity.HIGH
    assert out[0].affected == ["a", "b"]


def test_profile_filters_and_overrides(vuln_apk):
    p = Profile(name="t", min_severity=Severity.HIGH, severity_overrides={"DLX-308": Severity.CRITICAL},
                disabled_rules=["DLX-404"])
    r = run_scan(vuln_apk, p, save=False)
    assert all(f.severity >= Severity.HIGH for f in r.findings)
    assert "DLX-404" not in {f.rule_id for f in r.findings}
    assert next(f for f in r.findings if f.rule_id == "DLX-308").severity == Severity.CRITICAL
    r2 = run_scan(vuln_apk, Profile(name="only", enabled_rules=["DLX-30*"]), save=False)
    assert {f.rule_id for f in r2.findings} <= {f"DLX-30{i}" for i in range(10)}
    assert r2.findings


def test_builtin_profiles_load_and_ci_gate(vuln_apk):
    for n in ("standard", "quick", "full", "ci"):
        assert load_profile(n).name == n
    ci = load_profile("ci")
    r = run_scan(vuln_apk, ci, save=False)
    assert all(f.confidence >= Confidence.FIRM for f in r.findings)
    from deeplinkx.findings import exceeds

    assert exceeds(r.findings, ci.fail_on, ci.min_confidence)


def test_clean_app_has_no_high_findings(tmp_path):
    from fixtures.builders import make_cert

    cert, key = make_cert("Prod")
    t = manifest_tree("com.clean", target_sdk=34, app_attrs={"android:allowBackup": False,
                                                           "android:usesCleartextTraffic": False},
                      components=[activity(".Main", [intent_filter([MAIN], [LAUNCHER])], exported=True),
                                  activity(".Inner", exported=False)])
    apk = build_apk(tmp_path / "clean.apk", t, v2_certs=[cert])
    r = run_scan(str(apk), "standard", save=False)
    assert [f for f in r.findings if f.severity >= Severity.MEDIUM] == []
    assert r.summary["risk_level"] in ("None", "Low", "Info")


def test_yaml_rules(tmp_path, vuln_apk):
    f = tmp_path / "org.yaml"
    f.write_text(textwrap.dedent("""
        rules:
          - id: ORG-001
            title: Debug screens exported
            severity: high
            category: Policy
            description: No debug screen may be exported.
            remediation: Remove it.
            tags: [policy]
            when:
              kind: [activity]
              exported: true
              guard: none
              name_regex: "Debug"
          - id: ORG-002
            title: Payment scheme is used
            severity: medium
            description: custom scheme check
            when:
              scheme: [myshop]
              indicators: [sink_webview_load]
          - id: ORG-003
            title: App requests SMS
            severity: low
            description: sms
            when:
              uses_permission: [android.permission.SEND_SMS]
              debuggable: true
    """))
    r = run_scan(vuln_apk, Profile(name="y", rule_files=[str(f)]), save=False)
    byid = {}
    for x in r.findings:
        byid.setdefault(x.rule_id, []).append(x)
    assert [x.component for x in byid["ORG-001"]] == ["com.shop.demo.DebugActivity"]
    assert byid["ORG-001"][0].source == "yaml:org.yaml"
    assert [x.component for x in byid["ORG-002"]] == ["com.shop.demo.DeepLinkActivity"]
    assert byid["ORG-003"][0].component is None


def test_yaml_rule_validation(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  - id: X\n    title: t\n    severity: nope\n    description: d\n")
    with pytest.raises(RuleError):
        load_yaml_rules(bad)
    bad.write_text("rules:\n  - id: X\n    title: t\n    severity: low\n    description: d\n    when: {typo: 1}\n")
    with pytest.raises(RuleError, match="unknown condition"):
        load_yaml_rules(bad)
    bad.write_text("rules:\n  - id: X\n    title: t\n    severity: low\n    description: d\n"
                   "    when: {name_regex: '('}\n")
    with pytest.raises(RuleError, match="regular expression"):
        load_yaml_rules(bad)
    reg = build_registry(Profile(rule_files=[str(bad)]), load_user_dirs=False)
    assert any("regular expression" in e for e in reg.errors)


def test_plugins(tmp_path, vuln_apk):
    d = tmp_path / "plugins"
    d.mkdir()
    (d / "legacy.py").write_text(textwrap.dedent("""
        def register(api):
            @api.rule("PLG-001", "Alias present", "medium", "Plugin", "An alias exists", "Remove it")
            def check(ctx, meta):
                for c in ctx.manifest.components:
                    if c.kind == "activity-alias":
                        yield ctx.hit(meta, c, key="alias")
            api.add_report_section(lambda report: {"title": "Plugin section", "items": [str(len(report["findings"]))]})
            api.add_testcase_generator(lambda link, ctx: [])
    """))
    (d / "broken.py").write_text("def register(api):\n    raise RuntimeError('boom')\n")
    (d / "nofunc.py").write_text("x = 1\n")
    reg = build_registry(Profile(plugin_dirs=[str(d)]), load_user_dirs=False)
    assert reg.plugins == ["legacy"] and len(reg.errors) == 2
    assert any("boom" in e for e in reg.errors)
    r = run_scan(vuln_apk, Profile(name="p", plugin_dirs=[str(d)]), save=False)
    assert any(f.rule_id == "PLG-001" and f.source == "plugin:legacy" for f in r.findings)
    assert r.sections and r.sections[0]["title"] == "Plugin section"
    assert len(r.rule_errors) == 2


def test_broken_rule_is_isolated(vuln_apk):
    reg = build_registry(load_user_dirs=False)
    reg.rules[0].fn = lambda ctx, meta: 1 / 0
    r = run_scan(vuln_apk, "standard", registry=reg, save=False)
    assert any("ZeroDivisionError" in e for e in r.rule_errors)
    assert r.findings


def test_history_status_and_diff(vuln_apk, tmp_path):
    store = Store(tmp_path / "s.db")
    r1 = run_scan(vuln_apk, "standard", store=store)
    assert r1.scan_id == 1 and r1.previous is None
    target = r1.findings[0]
    store.set_status("com.shop.demo", target.id, "false_positive", "reviewed")
    r2 = run_scan(vuln_apk, "standard", store=store)
    t2 = next(f for f in r2.findings if f.fingerprint == target.fingerprint)
    assert t2.status == Status.FALSE_POSITIVE
    assert r2.summary["active"] == r1.summary["active"] - 1
    assert r2.summary["by_status"]["false_positive"] == 1
    assert r2.previous["new"] == [] and r2.previous["resolved"] == []
    assert len(r2.previous["persisting"]) == len(r2.findings)
    scans = store.list_scans()
    assert [s["id"] for s in scans] == [2, 1] and scans[0]["package"] == "com.shop.demo"
    assert store.get_scan(1)["findings"][0]["rule_id"] == r1.findings[0].rule_id
    with pytest.raises(Exception):
        store.set_status("com.shop.demo", "zzzz", "open")
    assert store.prune(keep=1) == 1 and len(store.list_scans()) == 1
    assert store.delete_scan(2) and not store.list_scans()
