"""One call that runs the whole static pipeline: analyse -> rules -> dedupe -> status -> summary -> history."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from .analysis import AnalysisResult, analyze_apk
from .config import Profile, load_profile
from .findings import Store, apply_filters, dedupe, finalize, run_rules, summarize
from .models import Finding
from .rules import Registry, build_registry
from .version import TAGLINE, TOOL_NAME, __version__

Progress = Callable[[str, float, str], None]


@dataclass
class ScanReport:
    analysis: AnalysisResult
    findings: list[Finding]
    summary: dict
    profile: Profile
    created: str
    duration: float
    rule_errors: list[str] = field(default_factory=list)
    rules_run: int = 0
    scan_id: Optional[int] = None
    dynamic: Optional[dict] = None
    previous: Optional[dict] = None  # diff against the previous scan of the same package
    sections: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        a = self.analysis.to_dict()
        return {
            "meta": {
                "tool": TOOL_NAME, "version": __version__, "tagline": TAGLINE, "created": self.created,
                "profile": self.profile.name, "duration": round(self.duration, 3), "scan_id": self.scan_id,
                "rules_run": self.rules_run, "rule_errors": self.rule_errors,
            },
            "apk": a["apk"],
            "manifest": a["manifest"],
            "deep_links": a["deep_links"],
            "link_summary": a["link_summary"],
            "entry_points": a["entry_points"],
            "exposure": a["exposure"],
            "permissions": a["permissions"],
            "network_security": a["network_security"],
            "code": {k: v for k, v in a["code"].items() if k != "components"} | {
                "components": {n: {"reachable_methods": c["reachable_methods"], "host_check": c["host_check"],
                                   "kinds": sorted({i["kind"] for i in c["indicators"]}),
                                   "params": c["param_names"], "class_found": c["class_found"]}
                               for n, c in a["code"]["components"].items()}},
            "assetlinks": a["assetlinks"],
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "dynamic": self.dynamic,
            "diff": self.previous,
            "sections": self.sections,
            "warnings": a["warnings"],
        }


def run_scan(apk_path: str, profile: Optional[Profile | str] = None, progress: Optional[Progress] = None,
             store: Optional[Store] = None, save: bool = True, registry: Optional[Registry] = None,
             fetcher=None) -> ScanReport:
    if isinstance(profile, str) or profile is None:
        profile = load_profile(profile)
    t0 = time.monotonic()
    registry = registry or build_registry(profile)
    analysis = analyze_apk(apk_path, profile, progress, fetcher)
    run = run_rules(analysis, profile, registry, lambda s, f, m: progress and progress("rules", f, m))
    findings = apply_filters(dedupe(run.findings), profile)
    store = store if store is not None else (Store() if save else None)
    if store is not None:
        store.apply_statuses(analysis.manifest.package, findings)
    finalize(findings)
    summary = summarize(findings)
    report = ScanReport(
        analysis=analysis, findings=findings, summary=summary, profile=profile,
        created=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), duration=time.monotonic() - t0,
        rule_errors=run.errors, rules_run=run.executed,
    )
    for fn in registry.sections:
        try:
            sec = fn(report.to_dict())
            if isinstance(sec, dict):
                report.sections.append(sec)
        except Exception as exc:
            report.rule_errors.append(f"report section: {type(exc).__name__}: {exc}")
    if store is not None and save:
        prev = store.latest(analysis.manifest.package)
        body = report.to_dict()
        report.scan_id = store.save_scan(body)
        if prev is not None:
            report.previous = store.diff(prev, body)
    if progress:
        progress("done", 1.0, f"{len(findings)} findings")
    return report


def attach_dynamic(report: ScanReport, run) -> int:
    """Merge a DynamicRun into a ScanReport: dynamic findings are added and static exposure findings confirmed."""
    from .dynamic import confirm_static, findings_from_run
    from .findings import dedupe as _dedupe

    confirmed = confirm_static(report.findings, run)
    extra = findings_from_run(run)
    merged = _dedupe(report.findings + extra)
    store_pkg = report.analysis.manifest.package
    report.findings = finalize(apply_filters(merged, report.profile))
    report.summary = summarize(report.findings)
    report.dynamic = run.to_dict()
    report.dynamic["confirmed_static"] = confirmed
    report.dynamic["new_findings"] = len(extra)
    _ = store_pkg
    return confirmed
