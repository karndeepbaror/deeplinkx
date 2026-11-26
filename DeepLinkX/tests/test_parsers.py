import pytest

from deeplinkx.apk import Ref, open_apk, parse_axml, parse_dex, parse_manifest
from deeplinkx.apk.arsc import ResourceTable
from deeplinkx.apk.axml import element_to_xml
from deeplinkx.errors import ApkError
from fixtures.builders import (
    BROWSABLE, DEFAULT, LAUNCHER, MAIN, VIEW, activity, build_apk, build_arsc, build_axml, build_dex,
    intent_filter, make_cert, manifest_tree,
)


def _tree():
    return manifest_tree(
        "com.example.app",
        permissions=["android.permission.INTERNET"],
        app_attrs={"android:debuggable": True, "android:allowBackup": True},
        components=[
            activity("com.example.app.Main", [intent_filter([MAIN], [LAUNCHER])], exported=True),
            activity(".Deep", [intent_filter([VIEW], [DEFAULT, BROWSABLE],
                                             [{"scheme": "https", "host": "example.com", "pathPrefix": "/p"}],
                                             auto_verify=True)]),
            activity("Hidden"),
            ("provider", {"android:name": ".Prov", "android:authorities": "a.b;c.d"}, []),
            ("service", {"android:name": ".Svc", "android:exported": False}, []),
            ("activity-alias", {"android:name": ".Alias", "android:targetActivity": ".Deep",
                                "android:exported": True}, []),
        ],
    )


@pytest.mark.parametrize("utf8", [False, True])
def test_axml_roundtrip(utf8):
    root = parse_axml(build_axml(_tree(), utf8=utf8))
    assert root.tag == "manifest"
    assert root.get("package") == "com.example.app"
    assert root.get("versionCode") == 7
    app = root.find("application")
    assert app.get("debuggable") is True
    assert [c.tag for c in app.children][:2] == ["activity", "activity"]
    assert "android:name" in element_to_xml(root)


def test_axml_stripped_names_use_resource_ids():
    root = parse_axml(build_axml(_tree(), strip_names=True))
    app = root.find("application")
    assert app.get("debuggable") is True
    assert app.children[0].get("name") == "com.example.app.Main"


def test_axml_rejects_garbage():
    with pytest.raises(ApkError):
        parse_axml(b"not xml at all")
    data = build_axml(_tree())
    with pytest.raises(ApkError):
        parse_axml(data[:40])


def test_manifest_semantics():
    m = parse_manifest(parse_axml(build_axml(_tree())))
    assert m.package == "com.example.app"
    assert (m.min_sdk, m.target_sdk) == (21, 33)
    assert m.debuggable and m.allow_backup
    assert m.permission_names == ["android.permission.INTERNET"]
    main, deep, hidden, prov, svc, alias = m.components
    assert main.effective_exported
    assert deep.name == "com.example.app.Deep" and deep.effective_exported  # implicit via filter
    assert deep.filters[0].browsable and deep.filters[0].auto_verify
    assert deep.filters[0].data[0].path_kind() == ("prefix", "/p")
    assert hidden.name == "com.example.app.Hidden" and not hidden.effective_exported
    assert prov.authorities == ["a.b", "c.d"] and not prov.effective_exported  # target 33
    assert not svc.effective_exported
    assert alias.target_activity == "com.example.app.Deep"


def test_provider_exported_by_default_on_old_target():
    t = manifest_tree(target_sdk=16, components=[("provider", {"android:name": ".P",
                                                               "android:authorities": "x"}, [])])
    m = parse_manifest(parse_axml(build_axml(t)))
    assert m.components[0].effective_exported


def test_arsc_default_config_and_references():
    arsc, ids = build_arsc(
        {"string": {"app_name": "Real", "scheme": "myapp"}, "bool": {"yes": True}, "xml": {"nsc": "res/xml/n.xml"}},
        extra_configs={"string": {"app_name": "Wrong (mcc)"}},
    )
    table = ResourceTable(arsc)
    assert len(table) >= 4
    assert table.string_of(ids["@string/app_name"]) == "Real"
    assert table.value_of(ids["@bool/yes"]) is True
    assert table.name_of(ids["@string/scheme"]) == "@string/scheme"
    assert table.resolve(Ref(ids["@string/scheme"])) == "myapp"


def test_arsc_sparse_types():
    arsc, ids = build_arsc({"string": {"a": "A", "b": "B"}}, sparse=True)
    table = ResourceTable(arsc)
    assert table.string_of(ids["@string/b"]) == "B"


def test_manifest_with_resource_references():
    arsc, ids = build_arsc({"string": {"host": "res.example.org", "label": "Resolved App"}, "bool": {"exp": True}})
    t = manifest_tree(
        app_attrs={"android:label": Ref(ids["@string/label"])},
        components=[activity(".A", [intent_filter([VIEW], [DEFAULT, BROWSABLE],
                                                 [{"scheme": "https", "host": Ref(ids["@string/host"])}])],
                             exported=Ref(ids["@bool/exp"]))],
    )
    m = parse_manifest(parse_axml(build_axml(t)), ResourceTable(arsc))
    assert m.app_label == "Resolved App"
    assert m.components[0].filters[0].data[0].host == "res.example.org"
    assert m.components[0].exported is True


def _dex():
    return build_dex([
        {"name": "Lcom/example/app/Deep;", "super": "Landroid/app/Activity;", "source": "Deep.java",
         "interfaces": ["Ljava/lang/Runnable;"],
         "methods": [
             {"name": "<init>", "desc": "()V", "access": 0x10001,
              "code": [("invoke", "direct", "Landroid/app/Activity;", "<init>", "()V"), ("return-void",)]},
             {"name": "onCreate", "desc": "(Landroid/os/Bundle;)V", "access": 4,
              "code": [
                  ("const/4",), ("const-wide",), ("packed-switch", 3), ("fill-array", 4, 5), ("sparse-switch", 2),
                  ("goto",), ("if-eqz",), ("iget",), ("add-int",), ("const",),
                  ("const-string", "http://evil.example/"), ("const-string-jumbo", "javascript:alert(1)"),
                  ("new-instance", "Landroid/webkit/WebView;"),
                  ("invoke", "virtual", "Landroid/webkit/WebView;", "loadUrl", "(Ljava/lang/String;)V"),
                  ("invoke", "virtual", "Landroid/content/Intent;", "getData", "()Landroid/net/Uri;"),
                  ("return-void",),
              ]},
             {"name": "run", "desc": "()V", "access": 1, "code": [("nop",), ("return-void",)]},
         ]},
        {"name": "Lcom/example/app/Empty;", "methods": []},
    ])


def test_dex_scan_with_all_widths_and_payloads():
    dex = parse_dex(_dex())
    classes = {c.name: c for c in dex.classes()}
    assert set(classes) == {"com.example.app.Deep", "com.example.app.Empty"}
    deep = classes["com.example.app.Deep"]
    assert deep.superclass == "android.app.Activity"
    assert deep.interfaces == ["java.lang.Runnable"]
    assert deep.source_file == "Deep.java"
    on_create = deep.method("onCreate")[0]
    assert on_create.strings == ["http://evil.example/", "javascript:alert(1)"]
    assert on_create.new_instances == ["android.webkit.WebView"]
    sigs = [r.sig for _, r in on_create.invokes]
    assert sigs == ["Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V",
                    "Landroid/content/Intent;->getData()Landroid/net/Uri;"]
    assert deep.method("<init>")[0].invokes[0][1].name == "<init>"
    assert dex.bad_classes == 0


def test_dex_filter_and_errors():
    dex = parse_dex(_dex())
    only = list(dex.classes(only={"com.example.app.Empty"}))
    assert [c.name for c in only] == ["com.example.app.Empty"]
    with pytest.raises(ApkError):
        parse_dex(b"hello")
    broken = bytearray(_dex())
    broken[40:44] = b"\x00\x00\x00\x00"
    with pytest.raises(ApkError):
        parse_dex(bytes(broken))


def test_apk_container(tmp_path):
    cert, key = make_cert("Release Key")
    arsc, _ = build_arsc({"string": {"x": "y"}})
    path = build_apk(tmp_path / "a.apk", _tree(), resources=arsc, dex=[_dex(), _dex()],
                     files={"lib/arm64-v8a/libx.so": b"\x7fELF", "lib/x86_64/liby.so": b"\x7fELF",
                            "assets/a.json": b"{}"},
                     v1_cert=(cert, key), v2_certs=[cert], v3_certs=[cert])
    with open_apk(path) as apk:
        info = apk.info()
        assert info["package"] == "com.example.app"
        assert info["dex_files"] == ["classes.dex", "classes2.dex"]
        assert info["native_abis"] == ["arm64-v8a", "x86_64"]
        assert len(info["hashes"]["sha256"]) == 64
        sig = apk.signatures()
        assert sig["schemes"] == {"v1": True, "v2": True, "v3": True, "v3.1": False}
        assert len(sig["certificates"]) == 1  # same cert across schemes is merged
        c = sig["certificates"][0]
        assert sorted(c["schemes"]) == ["v1", "v2", "v3"]
        assert c["key_type"] == "EC" and not c["debug"] and not c["expired"] and not c["weak_hash"]
        assert apk.assets((".json",)) == ["assets/a.json"]
        assert "com.example.app" in apk.manifest_xml()


def test_apk_certificate_flags(tmp_path):
    expired, _k = make_cert("Android Debug", valid_days=10, start_offset_days=-400)
    weak, _k2 = make_cert("Weak", key_type="rsa")
    path = build_apk(tmp_path / "b.apk", _tree(), v2_certs=[expired, weak])
    sig = open_apk(path).signatures()
    by_cn = {c["subject"]: c for c in sig["certificates"]}
    dbg = by_cn["CN=Android Debug"]
    assert dbg["debug"] and dbg["expired"]
    w = by_cn["CN=Weak"]
    assert not w["weak_hash"] and w["key_type"] == "RSA" and w["key_bits"] == 2048


def test_unsigned_apk_and_errors(tmp_path):
    path = build_apk(tmp_path / "u.apk", _tree())
    assert open_apk(path).signatures()["signed"] is False
    with pytest.raises(ApkError):
        open_apk(tmp_path / "missing.apk")
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"nope")
    with pytest.raises(ApkError):
        open_apk(bad)
    import zipfile

    nozip = tmp_path / "noman.apk"
    with zipfile.ZipFile(nozip, "w") as z:
        z.writestr("hello.txt", "x")
    with pytest.raises(ApkError):
        open_apk(nozip)


def test_weak_signature_algorithm_names():
    from deeplinkx.apk.apk import is_weak_signature_algorithm as weak

    assert weak("sha1WithRSAEncryption") and weak("md5WithRSAEncryption") and weak("ecdsa-with-SHA1")
    assert not weak("sha256WithRSAEncryption") and not weak("ecdsa-with-SHA256")
