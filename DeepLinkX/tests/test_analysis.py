from deeplinkx.analysis import analyze_apk
from deeplinkx.analysis.assetlinks import verify_hosts
from deeplinkx.config import Profile


def _ep(res, short):
    return next(e for e in res.entry_points if e.component.short_name == short)


def test_inventory_and_entry_points(vuln_apk):
    res = analyze_apk(vuln_apk)
    uris = sorted(l.uri for l in res.deep_links)
    assert uris == ["https://shop.example.com/product*", "myshop://pay"]
    assert res.link_summary["app_links"] == 1 and res.link_summary["custom_scheme"] == 1
    names = {e.component.short_name for e in res.entry_points}
    assert names == {"MainActivity", "DeepLinkActivity", "WebViewActivity", "DebugActivity", "PaymentReceiver",
                     "DataProvider", "SyncService", "AdminActivity", "InternalAlias"}
    assert _ep(res, "AdminActivity").guard == "strong"
    assert _ep(res, "SyncService").guard == "weak"  # normal-level custom permission
    assert _ep(res, "DebugActivity").guard == "none"
    assert any("alias exposes" in u for u in _ep(res, "InternalAlias").unintended)
    assert any("debug" in u for u in _ep(res, "DebugActivity").unintended)
    assert _ep(res, "MainActivity").is_launcher
    assert res.exposure["exported_total"] == 9


def test_code_reachability(vuln_apk):
    res = analyze_apk(vuln_apk)
    dl = res.code.for_component("com.shop.demo.DeepLinkActivity")
    assert dl.class_found and dl.reachable >= 2
    kinds = dl.kinds()
    assert {"input_intent", "input_uri", "sink_webview_load", "intent_parse", "sink_redirect",
            "validation_weak"} <= kinds
    assert dl.host_check == "weak"
    # webview sink sits in route(), reached through onCreate -> route
    sink = dl.of("sink_webview_load")[0]
    assert [c.rsplit(".", 1)[-1] for c in sink.to_dict()["chain"]] == ["onCreate", "route"]
    assert "redirect" in dl.param_names
    assert any(s.category == "url" and s.value.startswith("http://legacy") for s in dl.strings)
    assert any(s.value == "delete_account" for s in dl.strings)
    wv = res.code.for_component("com.shop.demo.WebViewActivity")
    assert {"webview_setting", "webview_bridge"} <= wv.kinds()
    assert wv.of("sink_webview_load")[0].same_method_input
    assert "sink_command" in res.code.for_component("com.shop.demo.DebugActivity").kinds()
    assert "sink_sql" in res.code.for_component("com.shop.demo.DataProvider").kinds()
    assert "sink_file" in res.code.for_component("com.shop.demo.DataProvider").kinds()
    # the alias resolves to its target activity
    assert res.code.for_component("com.shop.demo.InternalAlias").class_found
    assert any(i.kind == "webview_setting" for i in res.code.app_wide)
    assert any(u.value.startswith("http://legacy") for u in res.code.urls)
    assert res.code.secrets


def test_network_security_and_permissions(vuln_apk):
    res = analyze_apk(vuln_apk)
    n = res.netsec
    assert n["present"] and n["base_cleartext"] and n["user_certs_trusted"] and n["debug_overrides"]
    assert n["domain_configs"][0]["domains"][0]["name"] == "shop.example.com"
    assert n["domain_configs"][0]["pinned"] and not n["domain_configs"][0]["cleartext"]
    assert "android.permission.SEND_SMS" in res.permissions["high_impact"]
    assert "com.shop.demo.SYNC" in res.permissions["weak_custom"]


def test_profile_can_skip_code(vuln_apk):
    res = analyze_apk(vuln_apk, Profile(code_analysis=False))
    assert not res.code.available and res.code.per_component == {}


def test_assetlinks_verification(vuln_apk):
    res = analyze_apk(vuln_apk)
    cert = res.apk["signing"]["certificates"][0]["sha256"]
    fp = ":".join(cert.upper()[i:i + 2] for i in range(0, 64, 2))

    def doc(pkg, fps):
        import json

        return json.dumps([{"relation": ["delegate_permission/common.handle_all_urls"],
                            "target": {"namespace": "android_app", "package_name": pkg,
                                       "sha256_cert_fingerprints": fps}}]).encode()

    cases = {
        "ok.example": (200, doc("com.shop.demo", [fp])),
        "bad.example": (200, doc("com.shop.demo", ["00:11"])),
        "other.example": (200, doc("com.other", [fp])),
        "gone.example": (404, b""),
        "redir.example": (301, b""),
        "junk.example": (200, b"<html>"),
    }

    def fetcher(url, timeout):
        host = url.split("/")[2]
        if host == "down.example":
            raise ConnectionError("refused")
        return cases[host]

    rows = verify_hosts(list(cases) + ["down.example"], "com.shop.demo", [cert], fetcher=fetcher)
    status = {r["host"]: r["status"] for r in rows}
    assert status == {"ok.example": "verified", "bad.example": "mismatch", "other.example": "not_listed",
                      "gone.example": "missing", "redir.example": "redirect", "junk.example": "invalid",
                      "down.example": "unreachable"}


def test_assetlinks_refuses_private_hosts():
    rows = verify_hosts(["localhost", "printer.local"], "a.b", ["00" * 32])
    assert {r["status"] for r in rows} == {"skipped"}
