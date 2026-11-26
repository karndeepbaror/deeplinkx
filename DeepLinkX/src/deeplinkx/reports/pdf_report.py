from __future__ import annotations

import io
from typing import Any
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether, PageBreak, PageTemplate, Paragraph, Preformatted,
                                Spacer, Table, TableStyle)

from .context import SEV_COLORS, SEVERITIES, build_context

INK = colors.HexColor("#101828")
MUTED = colors.HexColor("#667085")
LINE = colors.HexColor("#d0d5dd")
ACCENT = colors.HexColor("#0f9d8f")
NAVY = colors.HexColor("#0b1222")


def _c(sev: str):
    return colors.HexColor(SEV_COLORS.get(sev, "#6b8cff"))


def _wrap(text: str, width: int = 96) -> str:
    out = []
    for line in str(text).splitlines() or [""]:
        while len(line) > width:
            out.append(line[:width])
            line = "  " + line[width:]
        out.append(line)
    return "\n".join(out)


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "body": ParagraphStyle("body", parent=base["BodyText"], fontName="Helvetica", fontSize=9, leading=13,
                               textColor=INK, alignment=TA_LEFT),
        "small": ParagraphStyle("small", fontName="Helvetica", fontSize=7.5, leading=10, textColor=MUTED),
        "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=17, leading=21, textColor=INK, spaceBefore=6,
                             spaceAfter=8),
        "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=INK, spaceBefore=8,
                             spaceAfter=3),
        "label": ParagraphStyle("label", fontName="Helvetica-Bold", fontSize=7.5, leading=10, textColor=MUTED,
                                spaceBefore=6, spaceAfter=1),
        "mono": ParagraphStyle("mono", fontName="Courier", fontSize=7.5, leading=10, textColor=INK),
        "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=8, leading=10.5, textColor=INK),
        "cellb": ParagraphStyle("cellb", fontName="Helvetica-Bold", fontSize=8, leading=10.5, textColor=INK),
    }


def _p(text: Any, style) -> Paragraph:
    return Paragraph(escape(str(text)).replace("\n", "<br/>"), style)


def _chart(counts: dict[str, int]) -> Drawing:
    d = Drawing(440, 120)
    chart = HorizontalBarChart()
    chart.x, chart.y, chart.width, chart.height = 70, 8, 330, 104
    vals = [counts.get(s, 0) for s in reversed(SEVERITIES)]
    chart.data = [vals]
    chart.categoryAxis.categoryNames = [s.title() for s in reversed(SEVERITIES)]
    chart.categoryAxis.labels.fontSize = 8
    chart.categoryAxis.strokeColor = LINE
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(max(vals), 1) + 1
    chart.valueAxis.labels.fontSize = 7
    chart.valueAxis.strokeColor = LINE
    chart.valueAxis.visibleGrid = True
    chart.valueAxis.gridStrokeColor = colors.HexColor("#eaecf0")
    chart.bars.strokeColor = None
    for i, s in enumerate(reversed(SEVERITIES)):
        chart.bars[(0, i)].fillColor = _c(s)
    chart.barWidth = 9
    d.add(chart)
    return d


def _cover(canvas, doc) -> None:
    pass


def _page(canvas, doc) -> None:
    canvas.saveState()
    w, h = A4
    canvas.setFillColor(NAVY)
    canvas.rect(0, h - 12 * mm, w, 12 * mm, stroke=0, fill=1)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(15 * mm, h - 7.7 * mm, "DEEPLINK")
    canvas.setFillColor(colors.HexColor("#4fd1c5"))
    canvas.drawString(15 * mm + 44, h - 7.7 * mm, "X")
    canvas.setFillColor(colors.HexColor("#9aa7c7"))
    canvas.setFont("Helvetica", 7.5)
    canvas.drawRightString(w - 15 * mm, h - 7.7 * mm, "Android Deep Link Security Assessment")
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(15 * mm, 9 * mm, "Every Link Has an Entry Point. Secure Every Entry.")
    canvas.drawRightString(w - 15 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _table(rows, widths, header=True, zebra=True) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [("FONT", (0, 0), (-1, -1), "Helvetica", 8), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LINEBELOW", (0, 0), (-1, -1), 0.3, LINE), ("TOPPADDING", (0, 0), (-1, -1), 3),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f2f4f7")),
                  ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 7.5), ("TEXTCOLOR", (0, 0), (-1, 0), MUTED)]
    t.setStyle(TableStyle(style))
    return t


def render_pdf(report: dict[str, Any]) -> bytes:
    ctx = build_context(report)
    st = _styles()
    apk, summary, meta = report["apk"], report["summary"], report["meta"]
    buf = io.BytesIO()
    doc = BaseDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=20 * mm,
                          bottomMargin=16 * mm, title=f"DEEPLINK X - {apk['package']}", author="DEEPLINK X",
                          subject="Android deep link security assessment")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="f")
    doc.addPageTemplates([PageTemplate(id="p", frames=[frame], onPage=_page)])
    W = doc.width
    story: list = []

    # ---------------- cover / summary
    story.append(Spacer(1, 6 * mm))
    story.append(_p("DEEPLINK X", ParagraphStyle("t", fontName="Helvetica-Bold", fontSize=11, textColor=ACCENT,
                                                  spaceAfter=2)))
    story.append(_p("Security Assessment Report", ParagraphStyle("t2", fontName="Helvetica-Bold", fontSize=24,
                                                                  leading=28, textColor=INK, spaceAfter=4)))
    story.append(_p(f"{apk.get('app_label') or apk['package']} {apk.get('version_name') or ''}".strip(),
                    ParagraphStyle("t3", fontName="Helvetica", fontSize=13, textColor=INK, spaceAfter=2)))
    story.append(_p(apk["package"], st["mono"]))
    story.append(Spacer(1, 5 * mm))
    risk = summary["risk_score"]
    cards = [[_p("RISK SCORE", st["small"]), _p("ACTIVE FINDINGS", st["small"]), _p("DEEP LINKS", st["small"]),
              _p("EXPORTED COMPONENTS", st["small"])],
             [_p(f"{risk} / 100", ParagraphStyle("k", fontName="Helvetica-Bold", fontSize=17, textColor=colors.HexColor(ctx["risk_color"]))),
              _p(summary["active"], ParagraphStyle("k2", fontName="Helvetica-Bold", fontSize=17)),
              _p(report["link_summary"]["total"], ParagraphStyle("k3", fontName="Helvetica-Bold", fontSize=17)),
              _p(report["exposure"]["exported_total"], ParagraphStyle("k4", fontName="Helvetica-Bold", fontSize=17))],
             [_p(f"level: {summary['risk_level']}", st["small"]), _p(f"{summary['total']} total", st["small"]),
              _p(f"{report['link_summary']['app_links']} app links", st["small"]),
              _p(f"{report['exposure']['unprotected']} unprotected", st["small"])]]
    ct = Table(cards, colWidths=[W / 4] * 4)
    ct.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.6, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.3, LINE),
                            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
                            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                            ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    story += [ct, Spacer(1, 5 * mm)]

    story.append(_p("Severity distribution", st["h2"]))
    story.append(_chart(summary["by_severity"]))

    story.append(_p("APK information", st["h2"]))
    info = [[_p("File", st["cellb"]), _p(f"{apk['file_name']} ({ctx['size']})", st["cell"])],
            [_p("SHA-256", st["cellb"]), _p(apk["hashes"]["sha256"], st["mono"])],
            [_p("SHA-1", st["cellb"]), _p(apk["hashes"]["sha1"], st["mono"])],
            [_p("MD5", st["cellb"]), _p(apk["hashes"]["md5"], st["mono"])],
            [_p("Version", st["cellb"]), _p(f"{apk.get('version_name') or '-'} (code {apk.get('version_code')})", st["cell"])],
            [_p("SDK", st["cellb"]), _p(f"min {apk.get('min_sdk')}, target {apk.get('target_sdk')}, compile {apk.get('compile_sdk') or '-'}", st["cell"])],
            [_p("Flags", st["cellb"]), _p(", ".join(k for k, v in (("debuggable", apk.get("debuggable")),
                                                                   ("allowBackup", apk.get("allow_backup")),
                                                                   ("cleartext", apk.get("uses_cleartext"))) if v) or "none", st["cell"])],
            [_p("Code", st["cellb"]), _p(f"{len(apk['dex_files'])} dex file(s), {report['code']['classes']} classes, "
                                         f"{report['code']['methods']} app methods; ABIs: {', '.join(apk['native_abis']) or 'none'}", st["cell"])],
            [_p("Signature schemes", st["cellb"]), _p(ctx["schemes"], st["cell"])]]
    story.append(_table(info, [34 * mm, W - 34 * mm], header=False))
    story.append(Spacer(1, 3 * mm))
    story.append(_p(f"Scan: {meta['tool']} {meta['version']}, profile {meta['profile']}, {meta['created']}, "
                    f"{meta['duration']} s, {meta['rules_run']} rules.", st["small"]))
    diff = report.get("diff")
    if diff:
        story.append(_p(f"Compared with the previous scan: {len(diff['new'])} new, {len(diff['resolved'])} resolved, "
                        f"{len(diff['persisting'])} unchanged (risk {diff['risk_before']} to {diff['risk_after']}).", st["small"]))

    # ---------------- findings overview
    story.append(PageBreak())
    story.append(_p("Findings summary", st["h1"]))
    rows = [[_p("ID", st["cellb"]), _p("Severity", st["cellb"]), _p("Finding", st["cellb"]), _p("Component", st["cellb"]),
             _p("Conf.", st["cellb"])]]
    for f in report["findings"]:
        rows.append([_p(f["id"], st["cell"]), _p(f["severity"].title(), ParagraphStyle(
            "sv", fontName="Helvetica-Bold", fontSize=8, textColor=_c(f["severity"]))),
            _p(f"{f['title']} ({f['rule_id']})", st["cell"]),
            _p((f.get("component") or "app").rsplit(".", 1)[-1], st["cell"]), _p(f["confidence"].title(), st["cell"])])
    if len(rows) == 1:
        story.append(_p("No findings were produced for this scan.", st["body"]))
    else:
        story.append(_table(rows, [14 * mm, 20 * mm, W - 14 * mm - 20 * mm - 38 * mm - 18 * mm, 38 * mm, 18 * mm]))

    # ---------------- inventory
    story.append(PageBreak())
    story.append(_p("Deep link inventory", st["h1"]))
    rows = [[_p("URI", st["cellb"]), _p("Component", st["cellb"]), _p("Type", st["cellb"]), _p("Browsable", st["cellb"]),
             _p("Guard", st["cellb"])]]
    for l in report["deep_links"]:
        kind = "app link" if l["is_app_link"] else "web, unverified" if l["scheme"] in ("http", "https") else "custom scheme"
        rows.append([_p(l["uri"], st["mono"]), _p(l["component"].rsplit(".", 1)[-1], st["cell"]), _p(kind, st["cell"]),
                     _p("yes" if l["browsable"] else "no", st["cell"]), _p(l["permission"] or "-", st["cell"])])
    story.append(_table(rows, [62 * mm, 34 * mm, 28 * mm, 18 * mm, W - 142 * mm]) if len(rows) > 1 else
                 _p("No deep links declared.", st["body"]))
    story.append(_p("Entry points", st["h1"]))
    rows = [[_p("Component", st["cellb"]), _p("Kind", st["cellb"]), _p("Guard", st["cellb"]), _p("Notes", st["cellb"])]]
    for e in report["entry_points"]:
        notes = ("launcher; " if e["is_launcher"] else "") + "; ".join(e["unintended"])
        rows.append([_p(e["name"].rsplit(".", 1)[-1], st["cell"]), _p(e["kind"], st["cell"]),
                     _p(ctx["guard_label"][e["guard"]], st["cell"]), _p(notes or "-", st["cell"])])
    story.append(_table(rows, [42 * mm, 24 * mm, 36 * mm, W - 102 * mm]) if len(rows) > 1 else
                 _p("No exported components.", st["body"]))

    # ---------------- detail
    story.append(PageBreak())
    story.append(_p("Technical findings", st["h1"]))
    for f in report["findings"]:
        block: list = []
        head = Table([[_p(f"{f['id']}  {f['title']}", ParagraphStyle("fh", fontName="Helvetica-Bold", fontSize=10,
                                                                       leading=13, textColor=colors.white)),
                       _p(f["severity"].upper(), ParagraphStyle("fs", fontName="Helvetica-Bold", fontSize=8,
                                                                 textColor=colors.white, alignment=2))]],
                     colWidths=[W - 26 * mm, 26 * mm])
        head.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), _c(f["severity"])), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                  ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
        block.append(head)
        meta_line = f"Rule {f['rule_id']}  |  {f['category']}  |  confidence {f['confidence'].lower()}  |  score {f['score']}  |  status {f['status']}"
        block.append(_p(meta_line, st["small"]))
        if f.get("component"):
            block.append(_p(f"Component: {f['component']} ({f.get('component_kind')})", st["mono"]))
        block.append(_p("Technical explanation", st["label"]))
        block.append(_p(f["description"], st["body"]))
        if f.get("impact"):
            block.append(_p("Impact", st["label"]))
            block.append(_p(f["impact"], st["body"]))
        story.append(KeepTogether(block[:4]))
        story += block[4:]
        for e in f["evidence"][:4]:
            story.append(_p(f"Evidence: {e['title']} [{e['kind']}]", st["label"]))
            story.append(Preformatted(_wrap(e["content"][:1800]), st["mono"], dedent=0,
                                      maxLineLength=110))
        if f["reproduction"]:
            story.append(_p("Reproduction", st["label"]))
            for c in f["reproduction"][:3]:
                story.append(Preformatted(_wrap(c), st["mono"]))
        story.append(_p("Remediation", st["label"]))
        story.append(_p(f["remediation"], st["body"]))
        story.append(Spacer(1, 5 * mm))

    # ---------------- dynamic
    dyn = report.get("dynamic")
    if dyn:
        story.append(PageBreak())
        story.append(_p("Dynamic testing", st["h1"]))
        story.append(_p(f"{len(dyn['results'])} test cases on {dyn['device']['serial']}; outcomes: "
                        + ", ".join(f"{k} {v}" for k, v in dyn["counts"].items()), st["body"]))
        rows = [[_p("ID", st["cellb"]), _p("Category", st["cellb"]), _p("Case", st["cellb"]),
                 _p("Component", st["cellb"]), _p("Outcome", st["cellb"])]]
        for x in dyn["results"]:
            rows.append([_p(x["case"]["id"], st["cell"]), _p(x["case"]["category"], st["cell"]),
                         _p(x["case"]["name"], st["cell"]), _p(x["case"]["component"].rsplit(".", 1)[-1], st["cell"]),
                         _p(x["observation"]["outcome"], st["cell"])])
        story.append(_table(rows, [14 * mm, 28 * mm, 50 * mm, 40 * mm, W - 132 * mm]))

    # ---------------- configuration + signing
    story.append(PageBreak())
    story.append(_p("Configuration", st["h1"]))
    ns = report["network_security"]
    rows = [[_p("Permissions requested", st["cellb"]), _p(", ".join(p.replace("android.permission.", "") for p in
                                                                    report["permissions"]["requested"]) or "none", st["cell"])],
            [_p("High impact", st["cellb"]), _p(", ".join(report["permissions"]["high_impact"]) or "none", st["cell"])],
            [_p("Cleartext traffic", st["cellb"]), _p("allowed" if ns["base_cleartext"] else "blocked", st["cell"])],
            [_p("User CAs", st["cellb"]), _p("trusted" if ns["user_certs_trusted"] else "not trusted", st["cell"])],
            [_p("Certificate pins", st["cellb"]), _p(ns["pins"], st["cell"])]]
    story.append(_table(rows, [40 * mm, W - 40 * mm], header=False))
    if report.get("assetlinks"):
        story.append(_p("App Link verification", st["h2"]))
        rows = [[_p("Host", st["cellb"]), _p("Status", st["cellb"]), _p("Detail", st["cellb"])]]
        rows += [[_p(a["host"], st["cell"]), _p(a["status"], st["cell"]), _p(a["detail"], st["cell"])] for a in report["assetlinks"]]
        story.append(_table(rows, [50 * mm, 25 * mm, W - 75 * mm]))
    story.append(_p("Signing certificates", st["h1"]))
    for c in apk["signing"]["certificates"] or []:
        rows = [[_p("Subject", st["cellb"]), _p(c["subject"], st["cell"])], [_p("Issuer", st["cellb"]), _p(c["issuer"], st["cell"])],
                [_p("Valid", st["cellb"]), _p(f"{c['not_before'][:10]} to {c['not_after'][:10]}" + (" (expired)" if c["expired"] else ""), st["cell"])],
                [_p("Key", st["cellb"]), _p(f"{c['key_type']} {c['key_bits']} bit, {c['signature_algorithm']}", st["cell"])],
                [_p("Schemes", st["cellb"]), _p(", ".join(c["schemes"]), st["cell"])],
                [_p("SHA-256", st["cellb"]), _p(c["sha256"], st["mono"])]]
        story.append(_table(rows, [28 * mm, W - 28 * mm], header=False))
        story.append(Spacer(1, 3 * mm))
    if not apk["signing"]["certificates"]:
        story.append(_p("The package is not signed.", st["body"]))
    story.append(Spacer(1, 8 * mm))
    story.append(_p("DEEPLINK X is an open source Android deep link security auditor by Karndeep Baror "
                    "(github.com/karndeepbaror, x.com/karndeepbaror). Static findings are indicators and should be "
                    "confirmed. Use dynamic testing only on applications you own or are authorised to test.", st["small"]))
    doc.build(story)
    return buf.getvalue()
