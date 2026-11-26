"""Derives everything the HTML and PDF renderers need from a report dict."""
from __future__ import annotations

from typing import Any

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_COLORS = {"CRITICAL": "#ff3b5c", "HIGH": "#ff7a45", "MEDIUM": "#f5b638", "LOW": "#3fb8a5", "INFO": "#6b8cff"}
GUARD_LABEL = {"none": "no protection", "weak": "weak permission", "medium": "dangerous permission",
               "strong": "signature permission"}


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def build_context(report: dict[str, Any]) -> dict[str, Any]:
    summary = report["summary"]
    counts = summary["by_severity"]
    total = sum(counts.values()) or 1
    bars = [{"name": s, "label": s.title(), "count": counts.get(s, 0), "color": SEV_COLORS[s],
             "pct": round(100 * counts.get(s, 0) / total, 1)} for s in SEVERITIES]
    # donut segments (stroke-dasharray on a circle with r=15.915 => circumference 100)
    offset = 0.0
    segments = []
    for b in bars:
        if b["count"]:
            segments.append({"color": b["color"], "len": b["pct"], "offset": offset})
            offset += b["pct"]
    cats = [{"name": k, "count": v} for k, v in summary["by_category"].items()]
    maxcat = max([c["count"] for c in cats], default=1)
    for c in cats:
        c["pct"] = round(100 * c["count"] / maxcat)
    findings = report["findings"]
    risk = summary["risk_score"]
    sig = report["apk"]["signing"]
    schemes = ", ".join(k for k, v in sig["schemes"].items() if v) or "none"
    ctx = {
        "r": report, "meta": report["meta"], "apk": report["apk"], "m": report["manifest"], "summary": summary,
        "bars": bars, "segments": segments, "cats": cats, "findings": findings, "risk": risk,
        "risk_color": SEV_COLORS["CRITICAL"] if risk >= 75 else SEV_COLORS["HIGH"] if risk >= 50 else
        SEV_COLORS["MEDIUM"] if risk >= 25 else SEV_COLORS["LOW"],
        "size": human_size(report["apk"]["size"]), "schemes": schemes, "guard_label": GUARD_LABEL,
        "sev_colors": SEV_COLORS, "dynamic": report.get("dynamic"), "diff": report.get("diff"),
        "sections": report.get("sections") or [], "top": findings[:5],
        "components_by_kind": report["exposure"]["by_kind"],
    }
    return ctx
