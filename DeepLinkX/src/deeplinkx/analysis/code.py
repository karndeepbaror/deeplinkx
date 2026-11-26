"""DEX level indicators.

Builds a class hierarchy and a method level call graph from the DEX files, then
walks from the lifecycle / callback methods of every component and records which
framework APIs are reachable. The result is evidence ("this component can reach
WebView.loadUrl and also reads Intent data"), not proof of exploitability, so
everything is reported with a confidence level by the rules engine.
"""
from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from ..apk.apk import Apk
from ..apk.dex import Dex, descriptor_to_name
from ..errors import ApkError
from ..models import Component, Manifest

LIBRARY_PREFIXES = (
    "android.", "androidx.", "kotlin.", "kotlinx.", "java.", "javax.", "dalvik.", "com.google.android.",
    "com.google.firebase.", "com.google.gson.", "com.google.protobuf.", "com.android.", "org.apache.",
    "okhttp3.", "okio.", "retrofit2.", "com.squareup.", "org.jetbrains.", "io.reactivex.", "org.intellij.",
    "com.bumptech.", "org.json.", "com.facebook.", "com.fasterxml.", "dagger.", "javax.inject.",
    "org.greenrobot.", "io.grpc.", "org.slf4j.", "org.bouncycastle.", "com.crashlytics.", "io.flutter.",
    "com.unity3d.", "com.adjust.", "com.appsflyer.", "com.airbnb.", "coil.", "org.chromium.",
)

LIFECYCLE = {
    "activity": {"onCreate", "onNewIntent", "onStart", "onResume", "onRestart", "onPostCreate",
                 "onActivityResult", "onCreateView", "onAttachedToWindow"},
    "service": {"onCreate", "onStartCommand", "onStart", "onBind", "onHandleIntent", "onHandleWork",
                "onTaskRemoved", "onRebind", "onTransact", "handleMessage"},
    "receiver": {"onReceive"},
    "provider": {"onCreate", "query", "insert", "update", "delete", "getType", "openFile", "openAssetFile",
                 "call", "bulkInsert", "openTypedAssetFile", "applyBatch", "openFileHelper"},
}
LIFECYCLE["activity-alias"] = LIFECYCLE["activity"]

MAX_DEPTH = 16
MAX_NODES = 40000

# (kind, class descriptor or None for "any", method name, descriptor prefix or None)
API_TABLE: list[tuple[str, Optional[str], str, Optional[str]]] = []


def _api(kind: str, cls: Optional[str], names: str, desc: Optional[str] = None) -> None:
    for n in names.split():
        API_TABLE.append((kind, cls, n, desc))


_I = "Landroid/content/Intent;"
_U = "Landroid/net/Uri;"
_W = "Landroid/webkit/WebView;"
_S = "Ljava/lang/String;"
_api("input_intent", _I, "getData getDataString getStringExtra getExtras getParcelableExtra getSerializableExtra "
     "getIntExtra getBooleanExtra getStringArrayListExtra getAction getCharSequenceExtra getLongExtra "
     "getBundleExtra getParcelableArrayListExtra getByteArrayExtra getClipData")
_api("input_intent", None, "getIntent", "()Landroid/content/Intent;")
_api("input_uri", _U, "getQueryParameter getQueryParameters getHost getPath getLastPathSegment getPathSegments "
     "getScheme getAuthority getFragment getEncodedQuery getQuery getEncodedPath getQueryParameterNames")
_api("uri_parse", _U, "parse")
_api("uri_parse", "Ljava/net/URI;", "create <init>")
_api("uri_parse", "Ljava/net/URL;", "<init>")
_api("sink_webview_load", _W, "loadUrl loadData loadDataWithBaseURL postUrl")
_api("sink_webview_js", _W, "evaluateJavascript")
_api("webview_bridge", _W, "addJavascriptInterface")
_api("webview_setting", "Landroid/webkit/WebSettings;",
     "setJavaScriptEnabled setAllowFileAccess setAllowFileAccessFromFileURLs setAllowUniversalAccessFromFileURLs "
     "setAllowContentAccess setMixedContentMode setDomStorageEnabled")
_api("webview_debug", _W, "setWebContentsDebuggingEnabled")
_api("ssl_proceed", "Landroid/webkit/SslErrorHandler;", "proceed")
_api("sink_redirect", None, "startActivity startActivityForResult startActivities startActivityIfNeeded "
     "startActivityFromChild", "(Landroid/content/Intent;")
_api("sink_broadcast", None, "sendBroadcast sendOrderedBroadcast sendStickyBroadcast sendBroadcastAsUser",
     "(Landroid/content/Intent;")
_api("sink_service", None, "startService startForegroundService bindService stopService",
     "(Landroid/content/Intent;")
_api("pending_intent", "Landroid/app/PendingIntent;", "getActivity getBroadcast getService getActivities")
_api("intent_parse", _I, "parseUri getIntent")
_api("intent_build", _I, "setComponent setClassName setClass setPackage setData setDataAndType setAction "
     "putExtra addFlags setFlags fillIn replaceExtras")
_api("sink_sql", "Landroid/database/sqlite/SQLiteDatabase;",
     "rawQuery execSQL query delete update insert rawQueryWithFactory queryWithFactory replace")
_api("sink_command", "Ljava/lang/Runtime;", "exec")
_api("sink_command", "Ljava/lang/ProcessBuilder;", "start")
_api("sink_file", "Ljava/io/FileInputStream;", "<init>")
_api("sink_file", "Ljava/io/FileOutputStream;", "<init>")
_api("sink_file", "Ljava/io/File;", "<init>")
_api("sink_file", "Ljava/io/RandomAccessFile;", "<init>")
_api("sink_file", "Landroid/content/ContentResolver;", "openInputStream openFileDescriptor openOutputStream "
     "openAssetFileDescriptor")
_api("sink_file", "Landroid/os/ParcelFileDescriptor;", "open")
_api("sink_dynamic", "Ldalvik/system/DexClassLoader;", "<init>")
_api("sink_dynamic", "Ldalvik/system/PathClassLoader;", "<init>")
_api("sink_dynamic", "Ljava/lang/Class;", "forName")
_api("sink_dynamic", "Ljava/lang/System;", "load loadLibrary")
_api("sink_dynamic", "Ljava/lang/reflect/Method;", "invoke")
_api("sensitive_api", "Landroid/accounts/AccountManager;", "getAuthToken peekAuthToken getPassword setPassword "
     "invalidateAuthToken removeAccount addAccountExplicitly getUserData")
_api("sensitive_api", "Landroid/telephony/SmsManager;", "sendTextMessage sendMultipartTextMessage sendDataMessage")
_api("sensitive_api", "Landroid/telephony/TelephonyManager;", "getDeviceId getImei getLine1Number getSubscriberId")
_api("sensitive_api", "Landroid/app/admin/DevicePolicyManager;", "wipeData lockNow resetPassword setPasswordQuality")
_api("sensitive_api", "Landroid/content/pm/PackageInstaller;", "createSession openSession")
_api("sensitive_api", "Landroid/provider/Settings$Secure;", "putString putInt")
_api("sensitive_api", "Landroid/provider/Settings$System;", "putString putInt")
_api("sensitive_api", "Landroid/security/keystore/KeyGenParameterSpec$Builder;", "setUserAuthenticationRequired")
_api("sensitive_api", "Landroid/content/ClipboardManager;", "setPrimaryClip")
_api("sensitive_api", "Landroid/os/Process;", "killProcess")
_api("sensitive_api", "Landroid/app/ActivityManager;", "clearApplicationUserData")
_api("sensitive_api", "Landroid/content/SharedPreferences$Editor;", "clear remove")
_api("validation_equals", _S, "equals equalsIgnoreCase contentEquals")
_api("validation_weak", _S, "startsWith endsWith contains indexOf regionMatches")
_api("validation_pattern", "Ljava/util/regex/Pattern;", "matches matcher compile")
_api("validation_pattern", _S, "matches")
_api("validation_equals", "Landroid/text/TextUtils;", "equals")
_api("validation_equals", "Landroid/webkit/URLUtil;", "isHttpsUrl isNetworkUrl isValidUrl")
_api("validation_equals", "Ljava/util/Set;", "contains")
_api("validation_equals", "Ljava/util/List;", "contains")
_api("validation_equals", "Ljava/util/Collection;", "contains")
_api("log", "Landroid/util/Log;", "d i v w e wtf")
_api("sink_network", "Ljava/net/URL;", "openConnection openStream")
_api("sink_network", "Ljava/net/HttpURLConnection;", "connect getInputStream")
_api("sink_network", "Lokhttp3/OkHttpClient;", "newCall")
_api("sink_network", "Lokhttp3/Request$Builder;", "url")
_api("sink_ui_action", "Landroid/app/AlertDialog$Builder;", "setPositiveButton")
_api("auth_check", "Landroid/accounts/AccountManager;", "getAccounts getAccountsByType")
_api("auth_check", "Landroid/hardware/biometrics/BiometricPrompt;", "authenticate")
_api("auth_check", "Landroidx/biometric/BiometricPrompt;", "authenticate")
_api("auth_check", "Landroid/app/KeyguardManager;", "isKeyguardSecure isDeviceSecure")

_API_BY_NAME: dict[str, list[tuple[str, Optional[str], Optional[str]]]] = {}
for _k, _c, _n, _d in API_TABLE:
    _API_BY_NAME.setdefault(_n, []).append((_k, _c, _d))

URL_RE = re.compile(r"^(https?|ftp|file|content|javascript|data|intent|market)://|^javascript:|^data:text", re.I)
SECRET_RE = re.compile(r"(api[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token|bearer |client[_-]?secret"
                       r"|private[_-]?key)", re.I)
ACTION_WORDS = re.compile(r"(delete|remove|transfer|payment|pay\b|checkout|purchase|withdraw|logout|sign[_ -]?out|"
                          r"reset[_ -]?password|change[_ -]?password|otp|verify|confirm|unlink|wipe|admin|"
                          r"grant|approve|send[_ -]?money|login|signin|oauth|callback|redirect)", re.I)
PARAM_RE = re.compile(r"^(url|uri|link|redirect|redirect_uri|redirect_url|next|return|return_url|returnurl|"
                      r"continue|goto|target|dest|destination|path|file|page|callback|forward|u|r)$", re.I)


def match_api(ref_cls: str, name: str, desc: str, op: int = 0) -> list[str]:
    hits = _API_BY_NAME.get(name)
    if not hits:
        return []
    kinds = []
    for kind, cls, dprefix in hits:
        if cls is not None and cls != ref_cls:
            continue
        if dprefix is not None and not desc.startswith(dprefix):
            continue
        kinds.append(kind)
    return kinds


def pretty(sig: str) -> str:
    """Lcom/a/B;->m(I)V -> com.a.B.m"""
    if "->" not in sig:
        return sig
    cls, rest = sig.split("->", 1)
    return f"{descriptor_to_name(cls)}.{rest.split('(', 1)[0]}"


@dataclass
class Indicator:
    kind: str
    api: str
    method: str
    chain: list[str]
    same_method_input: bool = False

    def to_dict(self) -> dict:
        return {"kind": self.kind, "api": pretty(self.api), "method": pretty(self.method),
                "chain": [pretty(c) for c in self.chain], "same_method_input": self.same_method_input}


@dataclass
class StringHit:
    value: str
    method: str
    category: str

    def to_dict(self) -> dict:
        return {"value": self.value, "method": pretty(self.method), "category": self.category}


@dataclass
class ComponentCode:
    component: str
    class_found: bool = False
    roots: list[str] = field(default_factory=list)
    reachable: int = 0
    truncated: bool = False
    indicators: list[Indicator] = field(default_factory=list)
    strings: list[StringHit] = field(default_factory=list)
    host_check: str = "none"  # none | weak | strict
    param_names: list[str] = field(default_factory=list)

    def kinds(self) -> set[str]:
        return {i.kind for i in self.indicators}

    def of(self, *kinds: str) -> list[Indicator]:
        return [i for i in self.indicators if i.kind in kinds]

    def to_dict(self) -> dict:
        return {
            "component": self.component, "class_found": self.class_found, "roots": [pretty(r) for r in self.roots],
            "reachable_methods": self.reachable, "truncated": self.truncated,
            "indicators": [i.to_dict() for i in self.indicators],
            "strings": [s.to_dict() for s in self.strings],
            "host_check": self.host_check, "param_names": self.param_names,
        }


@dataclass
class CodeAnalysis:
    dex_files: int = 0
    classes: int = 0
    app_classes: int = 0
    methods: int = 0
    bad_classes: int = 0
    per_component: dict[str, ComponentCode] = field(default_factory=dict)
    app_wide: list[Indicator] = field(default_factory=list)
    urls: list[StringHit] = field(default_factory=list)
    secrets: list[StringHit] = field(default_factory=list)
    obfuscated: bool = False
    available: bool = True
    notes: list[str] = field(default_factory=list)

    def for_component(self, name: str) -> Optional[ComponentCode]:
        return self.per_component.get(name)

    def to_dict(self) -> dict:
        return {
            "available": self.available, "dex_files": self.dex_files, "classes": self.classes,
            "app_classes": self.app_classes, "methods": self.methods, "bad_classes": self.bad_classes,
            "obfuscated": self.obfuscated, "notes": self.notes,
            "components": {k: v.to_dict() for k, v in self.per_component.items()},
            "app_wide": [i.to_dict() for i in self.app_wide],
            "urls": [u.to_dict() for u in self.urls],
            "secrets": [s.to_dict() for s in self.secrets],
        }


@dataclass
class _M:
    cls: str
    name: str
    desc: str
    invokes: list[tuple[int, str, str, str]]
    strings: list[str]
    new_instances: list[str]

    @property
    def sig(self) -> str:
        return f"{self.cls}->{self.name}{self.desc}"


def is_library(dotted: str) -> bool:
    return dotted.startswith(LIBRARY_PREFIXES)


def _desc(dotted: str) -> str:
    return "L" + dotted.replace(".", "/") + ";"


class _Graph:
    def __init__(self) -> None:
        self.methods: dict[tuple[str, str, str], _M] = {}
        self.by_class: dict[str, dict[tuple[str, str], _M]] = {}
        self.super: dict[str, Optional[str]] = {}
        self.ifaces: dict[str, list[str]] = {}
        self.children: dict[str, list[str]] = {}
        self._desc_cache: dict[tuple[str, str, str], list[_M]] = {}

    def add_class(self, desc: str, sup: Optional[str], ifaces: list[str], methods: Iterable[_M]) -> None:
        self.super[desc] = sup
        self.ifaces[desc] = ifaces
        table = self.by_class.setdefault(desc, {})
        for m in methods:
            self.methods[(m.cls, m.name, m.desc)] = m
            table[(m.name, m.desc)] = m

    def finish(self) -> None:
        for c, s in self.super.items():
            if s:
                self.children.setdefault(s, []).append(c)
            for i in self.ifaces.get(c, []):
                self.children.setdefault(i, []).append(c)

    def resolve(self, op: int, cls: str, name: str, desc: str) -> list[_M]:
        key = (cls, name, desc)
        hit = self._desc_cache.get(key)
        if hit is not None:
            return hit
        found: list[_M] = []
        cur: Optional[str] = cls
        seen = set()
        while cur and cur not in seen:
            seen.add(cur)
            m = self.by_class.get(cur, {}).get((name, desc))
            if m is not None:
                found.append(m)
                break
            cur = self.super.get(cur)
        if op not in (0x70, 0x71, 0x76, 0x77) and name not in ("<init>", "<clinit>"):
            stack = list(self.children.get(cls, []))
            count = 0
            while stack and count < 40:
                c = stack.pop()
                if c in seen:
                    continue
                seen.add(c)
                m = self.by_class.get(c, {}).get((name, desc))
                if m is not None:
                    found.append(m)
                    count += 1
                stack.extend(self.children.get(c, []))
        self._desc_cache[key] = found
        return found

    def ancestors(self, cls: str) -> list[str]:
        out = []
        cur: Optional[str] = cls
        while cur and cur not in out and cur in self.by_class:
            out.append(cur)
            cur = self.super.get(cur)
        return out


ProgressFn = Callable[[str, float], None]


def analyze_code(apk: Apk, manifest: Manifest, progress: Optional[ProgressFn] = None) -> CodeAnalysis:
    result = CodeAnalysis()
    names = apk.dex_names
    if not names:
        result.available = False
        result.notes.append("APK has no classes.dex (native only or heavily packed)")
        return result
    graph = _Graph()
    short_names = 0
    for di, dn in enumerate(names):
        try:
            dex = Dex(apk.read_dex(dn), dn)
        except ApkError as exc:
            result.notes.append(f"{dn}: {exc}")
            continue
        result.dex_files += 1
        for cls in dex.classes(with_code=True):
            result.classes += 1
            if is_library(cls.name):
                continue
            result.app_classes += 1
            if len(cls.name.rsplit(".", 1)[-1]) <= 2:
                short_names += 1
            ms = []
            for m in cls.methods:
                result.methods += 1
                ms.append(_M(
                    cls=cls.descriptor, name=m.ref.name, desc=m.ref.desc,
                    invokes=[(op, r.cls, r.name, r.desc) for op, r in m.invokes],
                    strings=m.strings, new_instances=m.new_instances,
                ))
            sup = _desc(cls.superclass) if cls.superclass else None
            graph.add_class(cls.descriptor, sup, [_desc(i) for i in cls.interfaces], ms)
        result.bad_classes += dex.bad_classes
        if progress:
            progress("dex", (di + 1) / len(names))
    graph.finish()
    result.obfuscated = result.app_classes > 50 and short_names / max(result.app_classes, 1) > 0.5

    # ---- app wide facts (all non-library methods, not only reachable ones)
    seen_urls: set[str] = set()
    for m in graph.methods.values():
        for op, rc, rn, rd in m.invokes:
            for kind in match_api(rc, rn, rd, op):
                if kind in ("webview_setting", "webview_bridge", "webview_debug", "ssl_proceed", "sink_dynamic",
                            "sink_command"):
                    if len(result.app_wide) < 400:
                        result.app_wide.append(Indicator(kind, f"{rc}->{rn}{rd}", m.sig, [m.sig]))
        for s in m.strings:
            if len(s) < 6 or len(s) > 600:
                continue
            if URL_RE.match(s) and s not in seen_urls and len(result.urls) < 500:
                seen_urls.add(s)
                result.urls.append(StringHit(s, m.sig, "url"))
            if SECRET_RE.search(s) and len(result.secrets) < 100:
                if "=" in s or re.search(r"[A-Za-z0-9_\-]{24,}", s):
                    result.secrets.append(StringHit(s[:120], m.sig, "secret"))

    # ---- per component reachability
    comps = [c for c in manifest.components if c.enabled]
    for ci, comp in enumerate(comps):
        result.per_component[comp.name] = _analyze_component(graph, comp, manifest)
        if progress:
            progress("components", (ci + 1) / max(len(comps), 1))
    return result


def _roots(graph: _Graph, comp: Component, manifest: Manifest) -> tuple[Optional[str], list[_M]]:
    name = comp.name
    if comp.kind == "activity-alias" and comp.target_activity:
        name = comp.target_activity
    desc = _desc(name)
    if desc not in graph.by_class:
        return None, []
    want = LIFECYCLE.get(comp.kind, set()) | {"<init>", "<clinit>"}
    roots = []
    for anc in graph.ancestors(desc):
        for (mn, _md), m in graph.by_class[anc].items():
            if mn in want:
                roots.append(m)
    return desc, roots


def _analyze_component(graph: _Graph, comp: Component, manifest: Manifest) -> ComponentCode:
    cc = ComponentCode(component=comp.name)
    desc, roots = _roots(graph, comp, manifest)
    if desc is None:
        return cc
    cc.class_found = True
    cc.roots = [m.sig for m in roots]
    parent: dict[tuple[str, str, str], Optional[tuple[str, str, str]]] = {}
    queue: deque[tuple[_M, int]] = deque()
    for m in roots:
        k = (m.cls, m.name, m.desc)
        if k not in parent:
            parent[k] = None
            queue.append((m, 0))
    visited: list[_M] = []
    while queue:
        m, depth = queue.popleft()
        visited.append(m)
        if len(visited) >= MAX_NODES:
            cc.truncated = True
            break
        if depth >= MAX_DEPTH:
            continue
        succ: list[_M] = []
        for op, rc, rn, rd in m.invokes:
            if rc in graph.by_class or rc in graph.super:
                succ.extend(graph.resolve(op, rc, rn, rd))
        for inst in m.new_instances:
            idesc = _desc(inst)
            table = graph.by_class.get(idesc)
            if table and idesc != desc:
                succ.extend(table.values())
        for s in succ:
            k = (s.cls, s.name, s.desc)
            if k not in parent:
                parent[k] = (m.cls, m.name, m.desc)
                queue.append((s, depth + 1))
    cc.reachable = len(visited)

    def chain_of(m: _M) -> list[str]:
        out = []
        cur: Optional[tuple[str, str, str]] = (m.cls, m.name, m.desc)
        while cur is not None and len(out) < 20:
            out.append(f"{cur[0]}->{cur[1]}{cur[2]}")
            cur = parent.get(cur)
        out.reverse()
        return out

    seen_ind: set[tuple[str, str, str]] = set()
    seen_str: set[str] = set()
    params: set[str] = set()
    has_host = strict = weak = False
    for m in visited:
        kinds_here: set[str] = set()
        hits: list[tuple[str, str]] = []
        for op, rc, rn, rd in m.invokes:
            for kind in match_api(rc, rn, rd, op):
                kinds_here.add(kind)
                hits.append((kind, f"{rc}->{rn}{rd}"))
        input_here = bool({"input_intent", "input_uri"} & kinds_here)
        if "input_uri" in kinds_here and any(
                (rn in ("getHost", "getAuthority")) for _o, _c, rn, _d in m.invokes):
            has_host = True
            if kinds_here & {"validation_weak"}:
                weak = True
            if kinds_here & {"validation_equals", "validation_pattern"}:
                strict = True
        for kind, api in hits:
            if kind in ("log",) and not input_here:
                continue
            key = (kind, api, m.sig)
            if key in seen_ind:
                continue
            seen_ind.add(key)
            if len(cc.indicators) < 300:
                cc.indicators.append(Indicator(kind, api, m.sig, chain_of(m), input_here))
        for s in m.strings:
            if len(s) < 3 or len(s) > 400 or s in seen_str:
                continue
            cat = None
            if URL_RE.match(s):
                cat = "url"
            elif PARAM_RE.match(s):
                cat = "param"
                params.add(s)
            elif SECRET_RE.search(s):
                cat = "secret"
            elif ACTION_WORDS.search(s) and len(s) < 60:
                cat = "sensitive_word"
            if cat:
                seen_str.add(s)
                if len(cc.strings) < 120:
                    cc.strings.append(StringHit(s, m.sig, cat))
    cc.param_names = sorted(params)
    cc.host_check = "none" if not has_host else ("strict" if strict and not weak else "weak" if weak else "none")
    return cc
