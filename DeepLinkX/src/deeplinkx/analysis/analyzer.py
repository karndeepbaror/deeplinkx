from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..apk import open_apk
from ..config import Profile
from ..models import DeepLink, Manifest
from .assetlinks import Fetcher, candidate_hosts, verify_hosts
from .code import CodeAnalysis, analyze_code
from .entrypoints import EntryPoint, exposure_summary, find_entry_points
from .inventory import build_inventory, summarize_inventory
from .netsec import parse_network_security_config
from .permissions import analyze_permissions

Progress = Callable[[str, float, str], None]


@dataclass
class AnalysisResult:
    apk: dict
    manifest: Manifest
    deep_links: list[DeepLink]
    link_summary: dict
    entry_points: list[EntryPoint]
    exposure: dict
    permissions: dict
    netsec: dict
    code: CodeAnalysis
    assetlinks: list[dict] = field(default_factory=list)
    manifest_xml: str = ""
    warnings: list[str] = field(default_factory=list)
    duration: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "apk": self.apk,
            "manifest": self.manifest.to_dict(),
            "deep_links": [l.to_dict() for l in self.deep_links],
            "link_summary": self.link_summary,
            "entry_points": [e.to_dict() for e in self.entry_points],
            "exposure": self.exposure,
            "permissions": self.permissions,
            "network_security": self.netsec,
            "code": self.code.to_dict(),
            "assetlinks": self.assetlinks,
            "warnings": self.warnings,
            "duration": round(self.duration, 3),
        }


def analyze_apk(path: str, profile: Optional[Profile] = None, progress: Optional[Progress] = None,
                fetcher: Optional[Fetcher] = None) -> AnalysisResult:
    profile = profile or Profile()
    t0 = time.monotonic()

    def tick(stage: str, frac: float, msg: str = "") -> None:
        if progress:
            progress(stage, frac, msg)

    tick("open", 0.0, "opening archive")
    with open_apk(path) as apk:
        info = apk.info()
        tick("open", 1.0, f"{info['package']} {info['version_name'] or ''}".strip())
        manifest = apk.manifest
        xml = apk.manifest_xml()
        tick("manifest", 1.0, f"{len(manifest.components)} components")
        links = build_inventory(manifest)
        tick("links", 1.0, f"{len(links)} deep links")
        eps = find_entry_points(manifest, links)
        tick("entry", 1.0, f"{len(eps)} exported entry points")
        perms = analyze_permissions(manifest)
        netsec = parse_network_security_config(apk.network_security_config(), manifest.uses_cleartext,
                                               manifest.target_sdk)
        tick("config", 1.0, "permissions and network config")
        if profile.code_analysis:
            code = analyze_code(apk, manifest, lambda s, f: tick("code", f, s))
        else:
            code = CodeAnalysis(available=False, notes=["code analysis disabled by profile"])
        tick("code", 1.0, f"{code.methods} methods indexed")
        assetlinks: list[dict] = []
        if profile.verify_assetlinks:
            hosts = candidate_hosts(links)
            certs = [c["sha256"] for c in info["signing"]["certificates"]]
            assetlinks = verify_hosts(hosts, manifest.package, certs, profile.assetlinks_timeout, fetcher)
        tick("assetlinks", 1.0, f"{len(assetlinks)} hosts checked")
        warnings = list(apk.warnings)
    return AnalysisResult(
        apk=info, manifest=manifest, deep_links=links, link_summary=summarize_inventory(links),
        entry_points=eps, exposure=exposure_summary(eps, manifest), permissions=perms, netsec=netsec,
        code=code, assetlinks=assetlinks, manifest_xml=xml, warnings=warnings,
        duration=time.monotonic() - t0,
    )
