"""Turns dynamic observations into findings and confirms static ones."""
from __future__ import annotations

from ..models import Confidence, Evidence, Finding, Severity, Status
from .runner import CaseResult, DynamicRun

SOURCE = "dynamic"


def _evidence(r: CaseResult) -> list[Evidence]:
    ev = [Evidence("command", f"{r.case.id} {r.case.name}", r.command)]
    if r.stdout.strip():
        ev.append(Evidence("output", "adb output", (r.stdout + r.stderr).strip()[-1500:]))
    if r.logcat_excerpt:
        ev.append(Evidence("log", "logcat excerpt", r.logcat_excerpt[-2500:]))
    if r.screenshot:
        ev.append(Evidence("file", "screenshot", r.screenshot))
    return ev


def _mk(rule_id: str, title: str, sev: Severity, conf: Confidence, category: str, desc: str, fix: str,
        r: CaseResult, key: str, impact: str = "") -> Finding:
    return Finding(
        rule_id=rule_id, title=title, severity=sev, confidence=conf, category=category, description=desc,
        remediation=fix, component=r.case.component, impact=impact, evidence=_evidence(r),
        reproduction=[r.command], tags=["dynamic", r.case.category], key=key, source=SOURCE,
        affected=[r.case.component])


def findings_from_run(run: DynamicRun) -> list[Finding]:
    out: list[Finding] = []
    for r in run.results:
        o, c = r.observation, r.case
        comp = c.component.rsplit(".", 1)[-1]
        if o.outcome == "crash":
            exc = ", ".join(o.exceptions[:3]) or "unhandled exception"
            out.append(_mk(
                "DLX-501", "Component crashes on crafted input", Severity.MEDIUM, Confidence.CERTAIN, "Dynamic",
                f"{comp} crashed (FATAL EXCEPTION: {exc}) when it received test case {c.id} '{c.name}'. "
                "A crash that can be triggered by another app or a web link is a reliable denial of service.",
                "Validate and null-check every extra and URI part, catch parsing errors and fail gracefully.",
                r, f"crash:{c.name}", "Remote-triggerable denial of service and possible information leak in crash reports."))
        elif o.outcome == "anr":
            out.append(_mk("DLX-502", "Component hangs on crafted input (ANR)", Severity.MEDIUM, Confidence.CERTAIN,
                           "Dynamic", f"{comp} stopped responding for case {c.id} '{c.name}'.",
                           "Move heavy work off the main thread and bound input sizes.", r, f"anr:{c.name}"))
        if "canary_url_loaded" in o.flags and c.category in ("redirect", "host-confusion", "scheme-injection"):
            out.append(_mk(
                "DLX-503", "External URL from a deep link parameter was loaded", Severity.HIGH, Confidence.FIRM,
                "Dynamic",
                f"After case {c.id} '{c.name}' the canary host appeared in the device log together with a navigation "
                "or network message, so a URL controlled by the link was followed by the app.",
                "Allow-list the destination host with an exact comparison before navigating.", r,
                f"canary-loaded:{c.name}", "Open redirect / phishing through trusted deep links."))
        if o.outcome in ("provider_error",) and "sql_error" in o.flags:
            out.append(_mk(
                "DLX-504", "Content provider is injectable (SQL error from quote)", Severity.HIGH, Confidence.CERTAIN,
                "Dynamic", "A single quote in the selection argument produced an SQLiteException, which means the "
                "provider concatenates caller input into SQL.",
                "Use selectionArgs placeholders, a projection map and SQLiteQueryBuilder.setStrict(true).", r,
                "sql-error", "Read arbitrary tables of the app database."))
        if c.kind == "provider" and o.outcome == "data_returned" and "sql_error" not in o.flags and \
                c.name == "provider-query":
            out.append(_mk(
                "DLX-505", "Provider returned data to an unprivileged caller", Severity.HIGH, Confidence.CERTAIN,
                "Dynamic", "A read-only query from the shell user returned rows without any permission, which any "
                "installed app can repeat.", "Set exported=false or protect the provider with a signature permission.",
                r, "data-returned", "Disclosure of app data to other apps."))
        if c.name == "provider-traversal" and o.outcome in ("data_returned",):
            out.append(_mk("DLX-506", "Provider served a file for a traversal path", Severity.HIGH, Confidence.FIRM,
                           "Dynamic", "A content read with encoded ../ segments returned data.",
                           "Canonicalise paths and verify they stay inside the permitted directory.", r, "traversal"))
        if "sql_error" in o.flags and c.kind != "provider" and c.category in ("special-chars", "canary"):
            out.append(_mk("DLX-507", "SQL error triggered through a deep link parameter", Severity.HIGH,
                           Confidence.FIRM, "Dynamic",
                           "Special characters from the link ended up in a SQL statement and raised an exception.",
                           "Bind parameters instead of concatenating them.", r, f"sql-link:{c.name}"))
    return out


EXPOSURE_RULES = {"DLX-101", "DLX-102", "DLX-103", "DLX-104", "DLX-107", "DLX-108", "DLX-109"}


def confirm_static(findings: list[Finding], run: DynamicRun) -> int:
    """Raise the confidence of static exposure findings when the component really started for an unprivileged caller."""
    reached: dict[str, CaseResult] = {}
    for r in run.results:
        if r.observation.outcome in ("launched", "data_returned") and r.case.component not in reached:
            reached[r.case.component] = r
    confirmed = 0
    for f in findings:
        if f.source == SOURCE or f.component not in reached:
            continue
        if f.rule_id in EXPOSURE_RULES:
            r = reached[f.component]
            f.confidence = Confidence.CERTAIN
            if f.status == Status.OPEN:
                f.status = Status.CONFIRMED
            f.evidence.append(Evidence("dynamic", f"Confirmed by {r.case.id} {r.case.name}", r.command))
            f.reproduction = list(dict.fromkeys(f.reproduction + [r.command]))
            confirmed += 1
    return confirmed
