"""Terminal renderings of reports, findings, history and rules."""
from __future__ import annotations

from typing import Any, Iterable, Optional

from .term import Console, pad, truncate, wrap
from .widgets import box, gauge, kv, sev_bars, sparkline, table

SEV_COLOR = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}
GUARD = {"none": ("none", "critical"), "weak": ("weak perm", "high"), "medium": ("dangerous perm", "medium"),
         "strong": ("signature", "low")}


def _short(name: str) -> str:
    return name.rsplit(".", 1)[-1] if name else "app"


def finding_rows(con: Console, findings: list[dict], limit: Optional[int] = None) -> list[list[str]]:
    rows = []
    for f in findings[:limit]:
        rows.append([con.c(f["id"], "muted"), con.sev(f["severity"][:4] if f["severity"] != "MEDIUM" else "MED"),
                     f["title"], con.c(_short(f.get("component") or "app"), "teal"), con.c(f["confidence"].lower(), "dim")])
    return rows


def print_summary(con: Console, report: dict[str, Any], top: int = 10) -> None:
    apk, s = report["apk"], report["summary"]
    w = min(con.width, 110)
    flags = [n for n, v in (("debuggable", apk.get("debuggable")), ("allowBackup", apk.get("allow_backup")),
                            ("cleartext", apk.get("uses_cleartext"))) if v]
    left = kv(con, [
        ("Package", con.c(apk["package"], "white", bold=True)),
        ("Version", f"{apk.get('version_name') or '-'} (code {apk.get('version_code')})"),
        ("SDK", f"min {apk.get('min_sdk')} · target {apk.get('target_sdk')}"),
        ("Size", f"{apk['size'] / 1024:.0f} KB · {len(apk['dex_files'])} dex · {', '.join(apk['native_abis']) or 'no native'}"),
        ("Signing", ", ".join(k for k, v in apk["signing"]["schemes"].items() if v) or con.c("unsigned", "warn")),
        ("Flags", con.c(", ".join(flags), "warn") if flags else con.c("none", "ok")),
        ("SHA-256", con.c(apk["hashes"]["sha256"][:40] + "…", "dim")),
    ], 10)
    for line in box(con, left, "APK", w):
        con.write("  " + line)
    risk = [con.c("Risk score  ", "muted") + gauge(con, s["risk_score"], 28),
            con.c("Risk level  ", "muted") + con.sev(s["risk_level"] if s["risk_level"] != "None" else "info", s["risk_level"].upper()),
            con.c("Deep links  ", "muted") + f"{report['link_summary']['total']}  "
            + con.c(f"({report['link_summary']['app_links']} app links, {report['link_summary']['custom_scheme']} custom)", "dim"),
            con.c("Exported    ", "muted") + f"{report['exposure']['exported_total']}/{report['exposure']['components_total']}  "
            + con.c(f"({report['exposure']['unprotected']} unprotected)", "dim"), ""] + sev_bars(con, s["by_severity"])
    for line in box(con, risk, "RISK", w):
        con.write("  " + line)
    findings = report["findings"]
    if findings:
        con.write("")
        con.write("  " + con.c(f"Top findings ({min(top, len(findings))} of {len(findings)})", "white", bold=True))
        for l in table(con, ["id", "sev", "finding", "component", "conf"], finding_rows(con, findings, top), max_width=w):
            con.write("  " + l)
    else:
        con.write("  " + con.c("No findings.", "ok", bold=True))
    d = report.get("diff")
    if d:
        con.write("")
        con.write("  " + con.c("Since previous scan: ", "muted") + con.c(f"{len(d['new'])} new", "bad") + ", "
                  + con.c(f"{len(d['resolved'])} resolved", "ok") + f", {len(d['persisting'])} unchanged  "
                  + con.c(f"(risk {d['risk_before']} → {d['risk_after']})", "dim"))
    for e in report["meta"].get("rule_errors", []):
        con.write("  " + con.c("rule error: ", "warn") + e)


def print_links(con: Console, report: dict[str, Any]) -> None:
    rows = []
    for l in report["deep_links"]:
        kind = con.c("app link", "ok") if l["is_app_link"] else con.c("web", "medium") if l["scheme"] in ("http", "https") \
            else con.c("custom", "info")
        rows.append([con.c(l["uri"], "white"), _short(l["component"]), kind, "yes" if l["browsable"] else "no",
                     l["permission"] or con.c("-", "dim")])
    if not rows:
        con.write("  " + con.c("No deep links declared.", "muted"))
        return
    for line in table(con, ["uri", "component", "type", "browsable", "permission"], rows):
        con.write("  " + line)


def print_entry_points(con: Console, report: dict[str, Any]) -> None:
    rows = []
    for e in report["entry_points"]:
        label, color = GUARD[e["guard"]]
        notes = ("launcher " if e["is_launcher"] else "") + "; ".join(e["unintended"])
        rows.append([_short(e["name"]), e["kind"], con.c(label, color), notes or con.c("-", "dim")])
    if not rows:
        con.write("  " + con.c("No exported components.", "muted"))
        return
    for line in table(con, ["component", "kind", "guard", "notes"], rows):
        con.write("  " + line)


def finding_detail_lines(con: Console, f: dict[str, Any], width: int) -> list[str]:
    inner = width - 6
    out = [con.sev(f["severity"]) + "  " + con.c(f["title"], "white", bold=True),
           con.c(f"{f['id']}  {f['rule_id']}  conf {f['confidence'].lower()}  score {f['score']}  status {f['status']}", "dim")]
    if f.get("component"):
        out.append(con.c("component ", "muted") + con.c(f["component"], "teal") + con.c(f"  ({f.get('component_kind')})", "dim"))
    def section(title: str, text: str, color: str = "white") -> None:
        out.append("")
        out.append(con.c(title.upper(), "muted", bold=True))
        for l in wrap(text, inner):
            out.append(con.c(l, color))
    section("Explanation", f["description"])
    if f.get("impact"):
        section("Impact", f["impact"])
    for e in f["evidence"]:
        out.append("")
        out.append(con.c(f"EVIDENCE · {e['title']}", "muted", bold=True) + con.c(f"  [{e['kind']}]", "dim"))
        for l in e["content"].splitlines()[:14]:
            out.append("  " + con.c(truncate(l, inner - 2), "violet"))
    if f["reproduction"]:
        out.append("")
        out.append(con.c("REPRODUCTION", "muted", bold=True))
        for r in f["reproduction"][:3]:
            for l in wrap(r, inner - 2):
                out.append("  " + con.c(l, "teal"))
    section("Remediation", f["remediation"], "ok")
    return out


def print_finding(con: Console, f: dict[str, Any]) -> None:
    for line in box(con, finding_detail_lines(con, f, min(con.width, 110)), f["id"], min(con.width, 110)):
        con.write("  " + line)


def print_history(con: Console, scans: list[dict]) -> None:
    if not scans:
        con.write("  " + con.c("No scans recorded yet.", "muted"))
        return
    rows = []
    for s in scans:
        c = s["counts"]
        rows.append([con.c(f"#{s['id']}", "teal"), s["created"].replace("T", " ").rstrip("Z"), s["package"],
                     s.get("version") or "-", str(s["risk"]),
                     " ".join(con.c(str(c.get(k, 0)), SEV_COLOR[k], bold=True) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")),
                     s["profile"]])
    for l in table(con, ["id", "when (UTC)", "package", "version", "risk", "C H M L", "profile"], rows):
        con.write("  " + l)
    pkgs = {}
    for s in scans:
        pkgs.setdefault(s["package"], []).append(s["risk"])
    for pkg, risks in pkgs.items():
        if len(risks) > 1:
            con.write("  " + con.c(pad(pkg, 34), "muted") + sparkline(con, list(reversed(risks))) + con.c("  risk trend", "dim"))


def print_rules(con: Console, rules: Iterable) -> None:
    rows = [[con.c(r.id, "teal"), con.sev(r.meta.severity.name[:4] if r.meta.severity.name != "MEDIUM" else "MED"),
             r.meta.category, r.meta.title, con.c(r.meta.source, "dim")] for r in rules]
    for l in table(con, ["id", "sev", "category", "title", "source"], rows):
        con.write("  " + l)


def print_batch(con: Console, rows: list[dict]) -> None:
    out = []
    for r in rows:
        if r.get("error"):
            out.append([r["file"], con.c("error", "bad"), "-", "-", "-", con.c(r["error"][:60], "dim")])
            continue
        s = r["summary"]
        c = s["by_severity"]
        out.append([r["file"], r["package"], str(s["risk_score"]), con.sev(s["risk_level"] if s["risk_level"] != "None" else "info",
                                                                       s["risk_level"].upper()),
                    " ".join(con.c(str(c.get(k, 0)), SEV_COLOR[k], bold=True) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")),
                    con.c(f"{r['duration']:.1f}s", "dim")])
    for l in table(con, ["file", "package", "risk", "level", "C H M L", "time"], out):
        con.write("  " + l)
