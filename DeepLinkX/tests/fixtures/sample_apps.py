"""A deliberately vulnerable demo application, built from scratch, used by many test modules."""
from __future__ import annotations

from .builders import (
    BROWSABLE, DEFAULT, LAUNCHER, MAIN, VIEW, activity, build_apk, build_arsc, build_dex, intent_filter,
    make_cert, manifest_tree,
)

PKG = "com.shop.demo"
APP = "Lcom/shop/demo/"


def _inv(kind, cls, name, desc):
    return ("invoke", kind, cls, name, desc)


def vulnerable_dex() -> bytes:
    intent = "Landroid/content/Intent;"
    uri = "Landroid/net/Uri;"
    webview = "Landroid/webkit/WebView;"
    string = "Ljava/lang/String;"
    return build_dex([
        {"name": APP + "MainActivity;", "super": "Landroid/app/Activity;", "methods": [
            {"name": "onCreate", "desc": "(Landroid/os/Bundle;)V", "access": 4, "code": [("return-void",)]}]},
        {"name": APP + "DeepLinkActivity;", "super": "Landroid/app/Activity;", "methods": [
            {"name": "onCreate", "desc": "(Landroid/os/Bundle;)V", "access": 4, "code": [
                _inv("virtual", APP + "DeepLinkActivity;", "getIntent", "()" + intent),
                _inv("virtual", intent, "getData", "()" + uri),
                _inv("virtual", uri, "getQueryParameter", f"({string}){string}"),
                ("const-string", "redirect"),
                ("const-string", "https://api.shop.example.com/v1/token?access_token=abcdefghijklmnopqrstuvwxyz0123"),
                _inv("virtual", uri, "getHost", "()" + string),
                _inv("virtual", string, "endsWith", f"({string})Z"),
                _inv("virtual", APP + "DeepLinkActivity;", "route", f"({string})V"),
                ("return-void",)]},
            {"name": "route", "desc": f"({string})V", "access": 2, "code": [
                ("const-string", "http://legacy.shop.example.com/redirect"),
                ("const-string", "delete_account"),
                ("new-instance", webview),
                _inv("virtual", webview, "loadUrl", f"({string})V"),
                _inv("static", intent, "parseUri", f"({string}I){intent}"),
                _inv("virtual", APP + "DeepLinkActivity;", "startActivity", f"({intent})V"),
                ("return-void",)]}]},
        {"name": APP + "WebViewActivity;", "super": "Landroid/app/Activity;", "methods": [
            {"name": "onCreate", "desc": "(Landroid/os/Bundle;)V", "access": 4, "code": [
                _inv("virtual", APP + "WebViewActivity;", "getIntent", "()" + intent),
                _inv("virtual", intent, "getStringExtra", f"({string}){string}"),
                _inv("virtual", "Landroid/webkit/WebSettings;", "setJavaScriptEnabled", "(Z)V"),
                _inv("virtual", "Landroid/webkit/WebSettings;", "setAllowFileAccessFromFileURLs", "(Z)V"),
                _inv("virtual", webview, "addJavascriptInterface", f"(Ljava/lang/Object;{string})V"),
                _inv("virtual", webview, "loadUrl", f"({string})V"),
                ("return-void",)]}]},
        {"name": APP + "DebugActivity;", "super": "Landroid/app/Activity;", "methods": [
            {"name": "onCreate", "desc": "(Landroid/os/Bundle;)V", "access": 4, "code": [
                _inv("virtual", "Ljava/lang/Runtime;", "exec", f"({string})Ljava/lang/Process;"),
                ("return-void",)]}]},
        {"name": APP + "PaymentReceiver;", "super": "Landroid/content/BroadcastReceiver;", "methods": [
            {"name": "onReceive", "desc": f"(Landroid/content/Context;{intent})V", "access": 1, "code": [
                _inv("virtual", intent, "getStringExtra", f"({string}){string}"),
                ("const-string", "transfer"),
                _inv("virtual", "Landroid/telephony/SmsManager;", "sendTextMessage",
                     f"({string}{string}{string}Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V"),
                ("return-void",)]}]},
        {"name": APP + "DataProvider;", "super": "Landroid/content/ContentProvider;", "methods": [
            {"name": "query", "desc": f"({uri}[{string}{string}[{string}{string})Landroid/database/Cursor;",
             "access": 1, "code": [
                _inv("virtual", "Landroid/database/sqlite/SQLiteDatabase;", "rawQuery",
                     f"({string}[{string})Landroid/database/Cursor;"),
                ("return-void",)]},
            {"name": "openFile", "desc": f"({uri}{string})Landroid/os/ParcelFileDescriptor;", "access": 1, "code": [
                _inv("direct", "Ljava/io/File;", "<init>", f"({string})V"),
                ("return-void",)]}]},
        {"name": APP + "SyncService;", "super": "Landroid/app/Service;", "methods": [
            {"name": "onStartCommand", "desc": f"({intent}II)I", "access": 1, "code": [
                _inv("virtual", intent, "getStringExtra", f"({string}){string}"), ("return-void",)]}]},
        {"name": APP + "AdminActivity;", "super": "Landroid/app/Activity;", "methods": [
            {"name": "onCreate", "desc": "(Landroid/os/Bundle;)V", "access": 4, "code": [("return-void",)]}]},
        {"name": APP + "SettingsActivity;", "super": "Landroid/app/Activity;", "methods": [
            {"name": "onCreate", "desc": "(Landroid/os/Bundle;)V", "access": 4, "code": [("return-void",)]}]},
    ])


def vulnerable_manifest(arsc_ids: dict) -> tuple:
    from deeplinkx.apk.axml import Ref

    return manifest_tree(
        PKG, min_sdk=21, target_sdk=28,
        permissions=["android.permission.INTERNET", "android.permission.SEND_SMS",
                     "android.permission.READ_CONTACTS"],
        extra=[("permission", {"android:name": "com.shop.demo.SYNC", "android:protectionLevel": 0}, []),
               ("permission", {"android:name": "com.shop.demo.ADMIN", "android:protectionLevel": 2}, [])],
        app_attrs={"android:debuggable": True, "android:allowBackup": True,
                   "android:usesCleartextTraffic": True,
                   "android:networkSecurityConfig": Ref(arsc_ids["@xml/network"])},
        components=[
            activity(".MainActivity", [intent_filter([MAIN], [LAUNCHER])], exported=True),
            activity(".DeepLinkActivity", [
                intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "myshop", "host": "pay"}]),
                intent_filter([VIEW], [DEFAULT, BROWSABLE],
                              [{"scheme": "https", "host": "shop.example.com", "pathPrefix": "/product"}],
                              auto_verify=True)]),
            activity(".WebViewActivity", exported=True),
            activity(".DebugActivity", exported=True),
            ("receiver", {"android:name": ".PaymentReceiver"},
             [intent_filter(["com.shop.demo.PAY"])]),
            ("provider", {"android:name": ".DataProvider", "android:authorities": "com.shop.demo.data",
                          "android:exported": True, "android:grantUriPermissions": True}, []),
            ("service", {"android:name": ".SyncService", "android:exported": True,
                         "android:permission": "com.shop.demo.SYNC"}, []),
            activity(".AdminActivity", exported=True, permission="com.shop.demo.ADMIN"),
            activity(".SettingsActivity", exported=False),
            ("activity-alias", {"android:name": ".InternalAlias", "android:targetActivity": ".SettingsActivity",
                                "android:exported": True}, []),
        ],
    )


def network_config_tree() -> tuple:
    return ("network-security-config", {}, [
        ("base-config", {"cleartextTrafficPermitted": True}, [
            ("trust-anchors", {}, [("certificates", {"src": "system"}, []), ("certificates", {"src": "user"}, [])])]),
        ("domain-config", {"cleartextTrafficPermitted": False}, [
            ("domain", {"includeSubdomains": True, "#text": "shop.example.com"}, []),
            ("pin-set", {}, [("pin", {"digest": "SHA-256", "#text": "AAAA"}, [])])]),
        ("debug-overrides", {}, [("trust-anchors", {}, [("certificates", {"src": "user"}, [])])]),
    ])


def build_vulnerable_apk(path, sign: bool = True) -> str:
    from .builders import build_axml

    arsc, ids = build_arsc({"xml": {"network": "res/xml/network.xml"}})
    cert, key = make_cert("Shop Demo Release")
    return build_apk(
        path, vulnerable_manifest(ids), resources=arsc, dex=[vulnerable_dex()],
        files={"res/xml/network.xml": build_axml(network_config_tree())},
        v1_cert=(cert, key) if sign else None, v2_certs=[cert] if sign else None,
    )
