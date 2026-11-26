from __future__ import annotations

from typing import Optional

from ..apk.axml import Element


def _b(v) -> Optional[bool]:
    return v if isinstance(v, bool) else None


def parse_network_security_config(root: Optional[Element], manifest_cleartext: Optional[bool],
                                  target_sdk: Optional[int]) -> dict:
    """Summarise network-security-config. Without a file, platform defaults apply."""
    default_cleartext = (target_sdk or 0) < 28
    info = {
        "present": root is not None,
        "base_cleartext": manifest_cleartext if manifest_cleartext is not None else default_cleartext,
        "user_certs_trusted": (target_sdk or 0) < 24,
        "domain_configs": [],
        "pins": 0,
        "debug_overrides": False,
        "cleartext_domains": [],
    }
    if root is None:
        return info
    base = root.find("base-config")
    if base is not None:
        ct = _b(base.get("cleartextTrafficPermitted"))
        if ct is not None:
            info["base_cleartext"] = ct
        anchors = base.find("trust-anchors")
        if anchors is not None:
            info["user_certs_trusted"] = any(c.get("src") == "user" for c in anchors.findall("certificates"))
        elif root is not None:
            info["user_certs_trusted"] = (target_sdk or 0) < 24
    for dc in root.findall("domain-config"):
        domains = [{"name": d.text.strip() if d.text else "", "subdomains": bool(_b(d.get("includeSubdomains")))}
                   for d in dc.findall("domain")]
        ct = _b(dc.get("cleartextTrafficPermitted"))
        pins = dc.find("pin-set")
        entry = {
            "domains": domains,
            "cleartext": ct if ct is not None else info["base_cleartext"],
            "pinned": pins is not None,
            "pin_count": len(pins.findall("pin")) if pins is not None else 0,
        }
        info["pins"] += entry["pin_count"]
        info["domain_configs"].append(entry)
        if entry["cleartext"]:
            info["cleartext_domains"].extend(d["name"] for d in domains if d["name"])
    info["debug_overrides"] = root.find("debug-overrides") is not None
    return info
