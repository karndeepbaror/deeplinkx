from __future__ import annotations

from typing import Any, Optional

from ..errors import ManifestError
from ..models import Component, DataSpec, IntentFilter, Manifest
from .arsc import ResourceTable
from .axml import Element, Ref

PROTECTION_BASE = {0: "normal", 1: "dangerous", 2: "signature", 3: "signatureOrSystem"}
PROTECTION_FLAGS = {
    0x10: "privileged", 0x20: "development", 0x40: "appop", 0x80: "pre23",
    0x100: "installer", 0x200: "verifier", 0x400: "preinstalled", 0x800: "setup",
    0x1000: "instant", 0x2000: "runtime", 0x4000: "oem", 0x8000: "vendorPrivileged",
    0x10000: "textClassifier", 0x20000: "wellbeing", 0x40000: "documenter",
    0x80000: "configurator", 0x100000: "incidentReportApprover",
    0x200000: "appPredictor", 0x400000: "companion", 0x800000: "retailDemo",
}


def _bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "1", "0xffffffff", "0xffff"):
            return True
        if low in ("false", "0", "0x0"):
            return False
    return None


def _int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


class _Resolver:
    def __init__(self, table: Optional[ResourceTable]):
        self.table = table

    def __call__(self, value: Any) -> Any:
        if self.table is not None and isinstance(value, Ref):
            return self.table.resolve(value)
        return value

    def text(self, value: Any) -> Optional[str]:
        v = self(value)
        if v is None:
            return None
        if isinstance(v, Ref):
            return None
        if isinstance(v, bool):
            return "true" if v else "false"
        return str(v)


def _qualify(pkg: str, name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    if name.startswith("."):
        return pkg + name
    if "." not in name:
        return f"{pkg}.{name}"
    return name


def protection_string(level: Any) -> str:
    n = _int(level)
    if n is None:
        return str(level) if level is not None else "normal"
    base = PROTECTION_BASE.get(n & 0x0F, "normal")
    extras = [label for bit, label in PROTECTION_FLAGS.items() if n & bit]
    return "|".join([base] + extras)


def _data_spec(el: Element, res: _Resolver) -> DataSpec:
    def g(n: str) -> Optional[str]:
        return res.text(el.get(n))

    return DataSpec(
        scheme=g("scheme"), host=g("host"), port=g("port"), path=g("path"),
        path_prefix=g("pathPrefix"), path_pattern=g("pathPattern"),
        path_advanced_pattern=g("pathAdvancedPattern"), path_suffix=g("pathSuffix"),
        mime_type=g("mimeType"),
    )


def _intent_filter(el: Element, res: _Resolver) -> IntentFilter:
    f = IntentFilter()
    f.auto_verify = bool(_bool(res(el.get("autoVerify"))))
    f.priority = _int(res(el.get("priority")))
    for c in el.children:
        if c.tag == "action":
            n = res.text(c.get("name"))
            if n:
                f.actions.append(n)
        elif c.tag == "category":
            n = res.text(c.get("name"))
            if n:
                f.categories.append(n)
        elif c.tag == "data":
            f.data.append(_data_spec(c, res))
    return f


def _component(el: Element, pkg: str, target_sdk: Optional[int], res: _Resolver) -> Component:
    name = _qualify(pkg, res.text(el.get("name")))
    if not name:
        raise ManifestError(f"<{el.tag}> without a name")
    c = Component(kind=el.tag, name=name)
    c.exported = _bool(res(el.get("exported")))
    enabled = _bool(res(el.get("enabled")))
    c.enabled = True if enabled is None else enabled
    c.permission = res.text(el.get("permission"))
    c.read_permission = res.text(el.get("readPermission"))
    c.write_permission = res.text(el.get("writePermission"))
    c.launch_mode = res.text(el.get("launchMode"))
    c.task_affinity = res.text(el.get("taskAffinity"))
    c.process = res.text(el.get("process"))
    c.direct_boot_aware = bool(_bool(res(el.get("directBootAware"))))
    c.grant_uri_permissions = bool(_bool(res(el.get("grantUriPermissions"))))
    if el.tag == "activity-alias":
        c.target_activity = _qualify(pkg, res.text(el.get("targetActivity")))
    auth = res.text(el.get("authorities"))
    if auth:
        c.authorities = [a.strip() for a in auth.split(";") if a.strip()]
    for child in el.children:
        if child.tag == "intent-filter":
            c.filters.append(_intent_filter(child, res))
        elif child.tag == "meta-data":
            key = res.text(child.get("name"))
            if key:
                val = res(child.get("value"))
                if val is None:
                    val = res(child.get("resource"))
                c.meta_data[key] = str(val) if val is not None else ""
        elif child.tag == "path-permission":
            c.path_permissions.append({
                "path": res.text(child.get("path")),
                "pathPrefix": res.text(child.get("pathPrefix")),
                "pathPattern": res.text(child.get("pathPattern")),
                "permission": res.text(child.get("permission")),
                "readPermission": res.text(child.get("readPermission")),
                "writePermission": res.text(child.get("writePermission")),
            })
        elif child.tag == "grant-uri-permission":
            c.attrs.setdefault("grant_uri_patterns", []).append({
                "path": res.text(child.get("path")),
                "pathPrefix": res.text(child.get("pathPrefix")),
                "pathPattern": res.text(child.get("pathPattern")),
            })
    if c.exported is not None:
        c.effective_exported = c.exported
    elif el.tag == "provider":
        c.effective_exported = target_sdk is None or target_sdk <= 16
    else:
        c.effective_exported = bool(c.filters)
    return c


def parse_manifest(root: Element, table: Optional[ResourceTable] = None) -> Manifest:
    if root.tag != "manifest":
        raise ManifestError(f"root element is <{root.tag}>, expected <manifest>")
    res = _Resolver(table)
    m = Manifest()
    m.package = res.text(root.get("package")) or ""
    m.version_code = _int(res(root.get("versionCode")))
    m.version_name = res.text(root.get("versionName"))
    m.compile_sdk = _int(res(root.get("compileSdkVersion")))
    m.shared_user_id = res.text(root.get("sharedUserId"))

    sdk = root.find("uses-sdk")
    if sdk is not None:
        m.min_sdk = _int(res(sdk.get("minSdkVersion")))
        m.target_sdk = _int(res(sdk.get("targetSdkVersion")))
        if m.target_sdk is None:
            m.target_sdk = m.min_sdk

    for tag in ("uses-permission", "uses-permission-sdk-23"):
        for el in root.findall(tag):
            n = res.text(el.get("name"))
            if n:
                m.uses_permissions.append({"name": n, "max_sdk": _int(res(el.get("maxSdkVersion")))})
    for el in root.findall("permission"):
        n = res.text(el.get("name"))
        if n:
            m.declared_permissions.append({
                "name": n,
                "protection": protection_string(res(el.get("protectionLevel"))),
            })
    for el in root.findall("uses-feature"):
        m.uses_features.append({
            "name": res.text(el.get("name")),
            "required": _bool(res(el.get("required"))),
        })

    app = root.find("application")
    if app is None:
        return m
    m.app_label = res.text(app.get("label"))
    m.app_class = _qualify(m.package, res.text(app.get("name")))
    m.debuggable = bool(_bool(res(app.get("debuggable"))))
    m.allow_backup = _bool(res(app.get("allowBackup")))
    m.uses_cleartext = _bool(res(app.get("usesCleartextTraffic")))
    m.test_only = bool(_bool(res(app.get("testOnly"))))
    m.request_legacy_storage = bool(_bool(res(app.get("requestLegacyExternalStorage"))))
    nsc = app.get("networkSecurityConfig")
    if isinstance(nsc, Ref) and table is not None:
        m.network_security_config = table.string_of(nsc)
    elif nsc:
        m.network_security_config = str(nsc)
    m.full_backup_content = res.text(app.get("fullBackupContent"))
    m.data_extraction_rules = res.text(app.get("dataExtractionRules"))
    m.app_attrs = {
        "persistent": _bool(res(app.get("persistent"))),
        "extract_native_libs": _bool(res(app.get("extractNativeLibs"))),
        "has_code": _bool(res(app.get("hasCode"))),
    }
    for el in app.children:
        if el.tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            m.components.append(_component(el, m.package, m.target_sdk, res))
    return m
