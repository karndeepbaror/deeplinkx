from __future__ import annotations

from ..models import Manifest

DANGEROUS = frozenset("""
android.permission.READ_CALENDAR android.permission.WRITE_CALENDAR android.permission.CAMERA
android.permission.READ_CONTACTS android.permission.WRITE_CONTACTS android.permission.GET_ACCOUNTS
android.permission.ACCESS_FINE_LOCATION android.permission.ACCESS_COARSE_LOCATION
android.permission.ACCESS_BACKGROUND_LOCATION android.permission.RECORD_AUDIO
android.permission.READ_PHONE_STATE android.permission.READ_PHONE_NUMBERS android.permission.CALL_PHONE
android.permission.ANSWER_PHONE_CALLS android.permission.READ_CALL_LOG android.permission.WRITE_CALL_LOG
android.permission.ADD_VOICEMAIL android.permission.USE_SIP android.permission.PROCESS_OUTGOING_CALLS
android.permission.BODY_SENSORS android.permission.ACTIVITY_RECOGNITION android.permission.SEND_SMS
android.permission.RECEIVE_SMS android.permission.READ_SMS android.permission.RECEIVE_WAP_PUSH
android.permission.RECEIVE_MMS android.permission.READ_EXTERNAL_STORAGE
android.permission.WRITE_EXTERNAL_STORAGE android.permission.READ_MEDIA_IMAGES
android.permission.READ_MEDIA_VIDEO android.permission.READ_MEDIA_AUDIO android.permission.POST_NOTIFICATIONS
android.permission.BLUETOOTH_CONNECT android.permission.BLUETOOTH_SCAN android.permission.NEARBY_WIFI_DEVICES
""".split())

HIGH_IMPACT = frozenset("""
android.permission.SEND_SMS android.permission.READ_SMS android.permission.RECEIVE_SMS
android.permission.CALL_PHONE android.permission.READ_CONTACTS android.permission.RECORD_AUDIO
android.permission.CAMERA android.permission.ACCESS_FINE_LOCATION android.permission.READ_CALL_LOG
android.permission.WRITE_EXTERNAL_STORAGE android.permission.REQUEST_INSTALL_PACKAGES
android.permission.SYSTEM_ALERT_WINDOW android.permission.MANAGE_EXTERNAL_STORAGE
android.permission.BIND_ACCESSIBILITY_SERVICE android.permission.BIND_DEVICE_ADMIN
android.permission.READ_LOGS android.permission.QUERY_ALL_PACKAGES
""".split())

SIGNATURE_PREFIXES = ("android.permission.BIND_", "android.permission.INTERNAL_", "android.permission.MANAGE_")

# guard strength ordering
NONE, WEAK, MEDIUM, STRONG = "none", "weak", "medium", "strong"
_ORDER = {NONE: 0, WEAK: 1, MEDIUM: 2, STRONG: 3}


def protection_of(name: str, manifest: Manifest) -> str:
    """normal | dangerous | signature | undeclared (custom permission not declared by this app)"""
    for p in manifest.declared_permissions:
        if p["name"] == name:
            base = p["protection"].split("|")[0]
            return base if base in ("normal", "dangerous", "signature", "signatureOrSystem") else "normal"
    if name in DANGEROUS:
        return "dangerous"
    if name.startswith(SIGNATURE_PREFIXES):
        return "signature"
    if name.startswith("android.permission."):
        return "normal"
    return "undeclared"


def guard_strength(permission: str | None, manifest: Manifest) -> str:
    if not permission:
        return NONE
    level = protection_of(permission, manifest)
    if level in ("signature", "signatureOrSystem"):
        return STRONG
    if level == "dangerous":
        return MEDIUM
    return WEAK


def strongest(*strengths: str) -> str:
    return max(strengths, key=lambda s: _ORDER[s])


def analyze_permissions(manifest: Manifest) -> dict:
    used = manifest.permission_names
    return {
        "requested": used,
        "dangerous": sorted(p for p in used if p in DANGEROUS),
        "high_impact": sorted(p for p in used if p in HIGH_IMPACT),
        "custom_declared": manifest.declared_permissions,
        "weak_custom": [
            p["name"] for p in manifest.declared_permissions
            if p["protection"].split("|")[0] in ("normal", "dangerous")
        ],
    }
