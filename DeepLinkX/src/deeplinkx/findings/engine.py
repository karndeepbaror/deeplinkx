from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterable, Optional

from ..analysis.analyzer import AnalysisResult
from ..config import Profile
from ..models import Confidence, Evidence, Finding, Severity, Status
from ..rules import Registry, RuleContext

SEVERITY_WEIGHT = {Severity.INFO: 0.5, Severity.LOW: 2.5, Severity.MEDIUM: 5.0, Severity.HIGH: 7.5,
                   Severity.CRITICAL: 9.5}
CONFIDENCE_FACTOR = {Confidence.TENTATIVE: 0.75, Confidence.FIRM: 0.92, Confidence.CERTAIN: 1.0}
ACTIVE = (Status.OPEN, Status.CONFIRMED)


@dataclass
class RuleRun:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    executed: int = 0
    skipped: int = 0


def score_finding(f: Finding) -> float:
    """0 - 10 score: severity weight scaled by confidence, small bonus for strong evidence."""
    base = SEVERITY_WEIGHT[f.severity] * CONFIDENCE_FACTOR[f.confidence]
    if any(e.kind == "code" for e in f.evidence) and f.severity >= Severity.MEDIUM:
        base += 0.3
    if f.reproduction and f.severity >= Severity.MEDIUM:
        base += 0.2
    return round(min(base, 10.0), 2)


def rule_enabled(rule_id: str, profile: Profile) -> bool:
    if rule_id in profile.disabled_rules:
        return False
    if profile.enabled_rules is not None:
        return any(rule_id == p or (p.endswith("*") and rule_id.startswith(p[:-1])) for p in profile.enabled_rules)
    return True


def run_rules(result: AnalysisResult, profile: Profile, registry: Registry,
              progress=None) -> RuleRun:
    ctx = RuleContext(result, profile)
    run = RuleRun(errors=list(registry.errors))
    rules = registry.rules
    for i, rule in enumerate(rules):
        if not rule_enabled(rule.id, profile):
            run.skipped += 1
            continue
        try:
            out = rule.run(ctx)
        except Exception as exc:  # one bad rule must not hide all other findings
            run.errors.append(f"{rule.id}: {type(exc).__name__}: {exc}")
            continue
        run.executed += 1
        for f in out:
            override = profile.severity_overrides.get(f.rule_id)
            if override is not None:
                f.severity = override
            run.findings.append(f)
        if progress:
            progress("rules", (i + 1) / max(len(rules), 1), rule.id)
    return run


def _merge_evidence(dst: list[Evidence], src: Iterable[Evidence]) -> None:
    have = {(e.kind, e.title, e.content) for e in dst}
    for e in src:
        k = (e.kind, e.title, e.content)
        if k not in have:
            dst.append(e)
            have.add(k)


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Merge findings with the same fingerprint (rule + component + key)."""
    merged: dict[str, Finding] = {}
    for f in findings:
        cur = merged.get(f.fingerprint)
        if cur is None:
            merged[f.fingerprint] = f
            continue
        cur.occurrences += f.occurrences
        cur.severity = max(cur.severity, f.severity)
        cur.confidence = max(cur.confidence, f.confidence)
        _merge_evidence(cur.evidence, f.evidence)
        for a in f.affected:
            if a not in cur.affected:
                cur.affected.append(a)
        for r in f.reproduction:
            if r not in cur.reproduction:
                cur.reproduction.append(r)
        for t in f.tags:
            if t not in cur.tags:
                cur.tags.append(t)
    return list(merged.values())


def apply_filters(findings: list[Finding], profile: Profile) -> list[Finding]:
    return [f for f in findings if f.severity >= profile.min_severity and f.confidence >= profile.min_confidence]


def finalize(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        f.score = score_finding(f)
    findings.sort(key=lambda f: (-int(f.severity), -f.score, f.rule_id, f.component or "", f.key))
    for i, f in enumerate(findings, start=1):
        f.id = f"F-{i:03d}"
    return findings


def risk_score(findings: Iterable[Finding]) -> int:
    findings = list(findings)
    """0 - 100. Each finding removes part of the remaining 'safety'; diminishing returns keep it bounded."""
    safety = 1.0
    for f in findings:
        if f.severity <= Severity.INFO:
            continue
        safety *= 1.0 - min(f.score / 10.0, 1.0) * 0.22
    value = int(round((1.0 - safety) * 100))
    return value if any(f.severity == Severity.CRITICAL for f in findings) else min(value, 94)


def risk_level(findings: list[Finding]) -> str:
    active = [f for f in findings if f.status in ACTIVE and f.severity > Severity.INFO]
    if not active:
        return "None"
    return max(f.severity for f in active).label


def summarize(findings: list[Finding]) -> dict:
    active = [f for f in findings if f.status in ACTIVE]
    by_sev = {s.name: 0 for s in sorted(Severity, reverse=True)}
    for f in active:
        by_sev[f.severity.name] += 1
    by_cat: dict[str, int] = {}
    by_status: dict[str, int] = {}
    by_conf = {c.name: 0 for c in sorted(Confidence, reverse=True)}
    for f in findings:
        by_status[f.status.value] = by_status.get(f.status.value, 0) + 1
    for f in active:
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
        by_conf[f.confidence.name] += 1
    return {
        "total": len(findings),
        "active": len(active),
        "by_severity": by_sev,
        "by_category": dict(sorted(by_cat.items(), key=lambda kv: -kv[1])),
        "by_status": by_status,
        "by_confidence": by_conf,
        "risk_score": risk_score(active),
        "risk_level": risk_level(findings),
    }


def exceeds(findings: list[Finding], level: Optional[Severity], min_conf: Confidence = Confidence.TENTATIVE) -> bool:
    if level is None:
        return False
    return any(f.status in ACTIVE and f.severity >= level and f.confidence >= min_conf for f in findings)
