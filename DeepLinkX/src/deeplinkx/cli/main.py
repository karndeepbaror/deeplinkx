from __future__ import annotations

import csv
import io
import json
import os
import platform
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

import click

from .. import version as V
from ..config import BUILTIN_PROFILES, Profile, home_dir, list_profiles, load_profile
from ..errors import DeeplinkXError, SafetyError
from ..findings import Store, exceeds
from ..models import Confidence, Severity
from ..reports import FORMATS, render, write_reports
from ..rules import build_registry
from ..scan import ScanReport, attach_dynamic, run_scan
from ..ui import Console, ScanDisplay, show_banner
from ..ui import views

EXIT_FINDINGS = 2
EXIT_SAFETY = 3


class DlxError(click.ClickException):
    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.exit_code = code

    def show(self, file=None) -> None:
        con = Console(sys.stderr)
        con.write(con.c("error: ", "bad", bold=True) + self.format_message())


class DlxGroup(click.Group):
    def invoke(self, ctx: click.Context):
        try:
            return super().invoke(ctx)
        except SafetyError as exc:
            raise DlxError(str(exc), EXIT_SAFETY) from exc
        except DeeplinkXError as exc:
            raise DlxError(str(exc), 1) from exc


def _con(ctx: click.Context, stream=None) -> Console:
    o = ctx.obj or {}
    return Console(stream or sys.stdout, force_color=True if o.get("color") else None,
                   animate=False if o.get("no_anim") else None)


def _overlay(store: Store, rep: dict) -> dict:
    """Apply the current finding statuses (which can change after a scan) to a stored report."""
    known = store.statuses(rep["apk"]["package"])
    for f in rep["findings"]:
        st = known.get(f["fingerprint"])
        if st:
            f["status"] = st["status"]
    return rep


def _collect_apks(paths: tuple[str, ...]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            out += sorted(path.rglob("*.apk"))
        elif path.is_file():
            out.append(path)
        else:
            raise DlxError(f"not found: {p}")
    if not out:
        raise DlxError("no APK files found")
    return out


def _profile(name: Optional[str], rules: tuple[str, ...], plugins: tuple[str, ...], assetlinks: bool, no_code: bool,
             fail_on: Optional[str], min_sev: Optional[str], min_conf: Optional[str],
             formats: Optional[str]) -> Profile:
    p = load_profile(name)
    p.rule_files += list(rules)
    p.plugin_dirs += list(plugins)
    if assetlinks:
        p.verify_assetlinks = True
    if no_code:
        p.code_analysis = False
    try:
        if fail_on:
            p.fail_on = Severity.parse(fail_on)
        if min_sev:
            p.min_severity = Severity.parse(min_sev)
        if min_conf:
            p.min_confidence = Confidence.parse(min_conf)
    except ValueError as exc:
        raise DlxError(str(exc)) from exc
    if formats:
        p.report_formats = [f.strip().lower() for f in formats.split(",") if f.strip()]
    return p


def _common(f):
    opts = [
        click.option("-p", "--profile", "profile_name", default=None, help="Scan profile name or YAML file."),
        click.option("--rules", "rules", multiple=True, type=click.Path(), help="Extra YAML rule file or directory."),
        click.option("--plugins", "plugins", multiple=True, type=click.Path(), help="Plugin directory."),
        click.option("--assetlinks", is_flag=True, help="Verify /.well-known/assetlinks.json for App Links (network)."),
        click.option("--no-code", is_flag=True, help="Skip DEX code analysis (manifest only)."),
        click.option("--fail-on", default=None, help="Exit with status 2 when a finding at this severity or above exists."),
        click.option("--min-severity", default=None, help="Hide findings below this severity."),
        click.option("--min-confidence", default=None, help="Hide findings below this confidence."),
        click.option("--no-history", is_flag=True, help="Do not record the scan in the local history."),
    ]
    for o in reversed(opts):
        f = o(f)
    return f


@click.group(cls=DlxGroup, context_settings={"help_option_names": ["-h", "--help"]},
             help=f"{V.TOOL_NAME} - {V.TAGLINE}\n\nAndroid deep link and entry point security auditor.")
@click.version_option(V.__version__, prog_name="deeplinkx")
@click.option("--no-color", is_flag=True, help="Disable colours (NO_COLOR is honoured too).")
@click.option("--color", is_flag=True, help="Force colours even when output is not a terminal.")
@click.option("--no-anim", is_flag=True, help="Disable animations.")
@click.pass_context
def cli(ctx: click.Context, no_color: bool, color: bool, no_anim: bool) -> None:
    if no_color:
        os.environ["NO_COLOR"] = "1"
    ctx.obj = {"color": color, "no_anim": no_anim}


# ------------------------------------------------------------------------------------------------ scan
def _scan_one(ctx, con: Console, apk: Path, profile: Profile, store: Optional[Store], registry, display: Optional[ScanDisplay],
              dyn: dict) -> ScanReport:
    progress = display.update if display else None
    report = run_scan(str(apk), profile, progress=progress, store=store, save=store is not None, registry=registry)
    if dyn.get("enabled"):
        from ..dynamic import Adb, DynamicRunner, SafetyPolicy

        policy = SafetyPolicy(authorized=dyn["authorized"], allow_physical=dyn["allow_physical"], allow_install=True)
        adb = Adb(dyn.get("adb"), serial=dyn.get("serial"), policy=policy, timeout=profile.dynamic.command_timeout)
        out_dir = Path(dyn["evidence"]) / (report.analysis.manifest.package) if dyn.get("evidence") else None
        runner = DynamicRunner(adb, report.analysis, policy, profile.dynamic, apk_path=str(apk), out_dir=out_dir,
                               generators=registry.generators, install=dyn["install"])
        run = runner.run(progress=progress)
        attach_dynamic(report, run)
        if store is not None and report.scan_id:
            store.delete_scan(report.scan_id)
            report.scan_id = store.save_scan(report.to_dict())
    return report


def _write_outputs(con: Console, report: ScanReport, profile: Profile, out_dir: str, quiet: bool) -> list[Path]:
    paths = write_reports(report.to_dict(), out_dir, profile.report_formats)
    if not quiet:
        con.write("")
        con.write("  " + con.c("Reports", "white", bold=True))
        for p in paths:
            con.write("   " + con.c("›", "teal") + f" {p}")
    return paths


@cli.command(help="Analyse one or more APKs (files or directories).")
@click.argument("apks", nargs=-1, required=True)
@_common
@click.option("-f", "--formats", default=None, help="Report formats, comma separated: html,json,pdf,sarif.")
@click.option("-o", "--out", "out_dir", default="deeplinkx-reports", show_default=True, help="Report output directory.")
@click.option("--json", "as_json", is_flag=True, help="Print the JSON report to stdout and nothing else.")
@click.option("-q", "--quiet", is_flag=True, help="Only print the final summary line.")
@click.option("-i", "--interactive", is_flag=True, help="Open the interactive findings browser afterwards.")
@click.option("-j", "--jobs", default=1, show_default=True, help="Parallel jobs when scanning several APKs.")
@click.option("--top", default=10, show_default=True, help="Findings shown in the terminal summary.")
@click.option("--dynamic", is_flag=True, help="Also run dynamic tests on an emulator (needs --authorized).")
@click.option("--authorized", is_flag=True, help="Confirm you are authorised to test this application.")
@click.option("--serial", default=None, help="adb device serial.")
@click.option("--allow-physical", is_flag=True, help="Allow a physical test device (isolated devices only).")
@click.option("--install", is_flag=True, help="Install the APK on the device before testing.")
@click.option("--adb", "adb_path", default=None, help="Path to the adb binary.")
@click.option("--evidence", default="deeplinkx-evidence", show_default=True, help="Dynamic evidence directory.")
@click.pass_context
def scan(ctx, apks, profile_name, rules, plugins, assetlinks, no_code, fail_on, min_severity, min_confidence, no_history,
         formats, out_dir, as_json, quiet, interactive, jobs, top, dynamic, authorized, serial, allow_physical, install,
         adb_path, evidence):
    files = _collect_apks(apks)
    profile = _profile(profile_name, rules, plugins, assetlinks, no_code, fail_on, min_severity, min_confidence, formats)
    registry = build_registry(profile)
    store = None if no_history else Store()
    dyn = {"enabled": dynamic, "authorized": authorized, "serial": serial, "allow_physical": allow_physical,
           "install": install, "adb": adb_path, "evidence": evidence}
    if dynamic and not authorized:
        raise SafetyError("dynamic testing requires --authorized. Only test applications you own or are explicitly "
                          "authorised to test, in an isolated environment.")
    con = _con(ctx, sys.stderr if as_json else sys.stdout)
    batch = len(files) > 1
    if not (as_json or quiet):
        show_banner(con, compact=batch)
    reports: list[tuple[Path, ScanReport]] = []
    rows: list[dict] = []

    def one(apk: Path, display: Optional[ScanDisplay]):
        t0 = time.monotonic()
        try:
            rep = _scan_one(ctx, con, apk, profile, store, registry, display, dyn)
            return apk, rep, None, time.monotonic() - t0
        except SafetyError:
            raise
        except DeeplinkXError as exc:
            return apk, None, str(exc), time.monotonic() - t0

    if not batch:
        apk = files[0]
        title = f"Scanning {apk.name}"
        if quiet or as_json:
            _, rep, err, _ = one(apk, None)
        else:
            with ScanDisplay(con, title, show_dynamic=dynamic) as disp:
                _, rep, err, _ = one(apk, disp)
        if err:
            raise DlxError(err)
        reports.append((apk, rep))
    else:
        done = 0
        results = []
        pool_size = max(1, jobs)
        if not (quiet or as_json):
            con.write(f"  Scanning {len(files)} APKs with {pool_size} job(s)")
        if pool_size == 1:
            for apk in files:
                results.append(one(apk, None))
                done += 1
                if not (quiet or as_json):
                    con.write(f"  {con.c(f'[{done}/{len(files)}]', 'teal')} {apk.name}")
        else:
            with ThreadPoolExecutor(pool_size) as pool:
                for r in pool.map(lambda a: one(a, None), files):
                    results.append(r)
                    done += 1
                    if not (quiet or as_json):
                        con.write(f"  {con.c(f'[{done}/{len(files)}]', 'teal')} {r[0].name}")
        for apk, rep, err, dur in results:
            if rep is None:
                rows.append({"file": apk.name, "error": err})
            else:
                reports.append((apk, rep))
                rows.append({"file": apk.name, "package": rep.analysis.manifest.package, "summary": rep.summary,
                             "duration": dur})

    if as_json:
        data = [r.to_dict() for _, r in reports]
        click.echo(json.dumps(data[0] if not batch else {"reports": data}, indent=2, default=str))
    else:
        for apk, rep in reports:
            sub = out_dir if not batch else str(Path(out_dir) / rep.analysis.manifest.package)
            if not quiet and not batch:
                con.write("")
                views.print_summary(con, rep.to_dict(), top)
            _write_outputs(con, rep, profile, sub, quiet or batch and False)
        if batch:
            con.write("")
            views.print_batch(con, rows)
            _write_batch_summary(out_dir, rows)
            con.write("  " + con.c("Batch summary: ", "muted") + str(Path(out_dir) / "batch-summary.json"))
        if quiet:
            for _, rep in reports:
                s = rep.summary
                click.echo(f"{rep.analysis.manifest.package} risk={s['risk_score']} level={s['risk_level']} "
                           f"active={s['active']}")
    if interactive and not batch and not as_json and sys.stdin.isatty() and con.is_tty:
        from ..ui.browser import FindingsBrowser

        rep = reports[0][1]
        pkg = rep.analysis.manifest.package

        def cb(f, status):
            if store is None:
                raise RuntimeError("history is disabled")
            store.set_status(pkg, f["id"], status)

        FindingsBrowser(con, rep.to_dict(), cb).run()
    failed = any(exceeds(r.findings, profile.fail_on, profile.min_confidence) for _, r in reports)
    if any(row.get("error") for row in rows) and not reports:
        ctx.exit(1)
    if failed:
        if not (quiet or as_json):
            con.write("")
            con.write("  " + con.c(f"✖ findings at or above {profile.fail_on.label} were found", "bad", bold=True))
        ctx.exit(EXIT_FINDINGS)


def _write_batch_summary(out_dir: str, rows: list[dict]) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "batch-summary.json").write_text(json.dumps(rows, indent=2, default=str), encoding="utf-8")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["file", "package", "risk", "level", "critical", "high", "medium", "low", "info", "error"])
    for r in rows:
        if r.get("error"):
            w.writerow([r["file"], "", "", "", "", "", "", "", "", r["error"]])
        else:
            s = r["summary"]
            c = s["by_severity"]
            w.writerow([r["file"], r["package"], s["risk_score"], s["risk_level"], c["CRITICAL"], c["HIGH"],
                        c["MEDIUM"], c["LOW"], c["INFO"], ""])
    (out / "batch-summary.csv").write_text(buf.getvalue(), encoding="utf-8")


@cli.command(help="Dynamic tests on an emulator (static scan first, then controlled deep link invocation).")
@click.argument("apk")
@_common
@click.option("--authorized", is_flag=True, help="Confirm you are authorised to test this application.")
@click.option("--serial", default=None)
@click.option("--allow-physical", is_flag=True)
@click.option("--install", is_flag=True, help="Install the APK on the device first.")
@click.option("--adb", "adb_path", default=None)
@click.option("--evidence", default="deeplinkx-evidence", show_default=True)
@click.option("--plan-only", is_flag=True, help="Print the generated test cases and exit (no device needed).")
@click.option("-f", "--formats", default=None)
@click.option("-o", "--out", "out_dir", default="deeplinkx-reports", show_default=True)
@click.option("--top", default=10)
@click.pass_context
def dynamic(ctx, apk, profile_name, rules, plugins, assetlinks, no_code, fail_on, min_severity, min_confidence, no_history,
            authorized, serial, allow_physical, install, adb_path, evidence, plan_only, formats, out_dir, top):
    if plan_only:
        from ..analysis import analyze_apk
        from ..dynamic import generate_cases

        profile = _profile(profile_name, rules, plugins, False, False, None, None, None, None)
        registry = build_registry(profile)
        analysis = analyze_apk(apk, profile)
        cases = generate_cases(analysis, profile.dynamic, registry.generators)
        con = _con(ctx)
        rows = [[con.c(c.id, "teal"), c.category, c.component.rsplit(".", 1)[-1], c.name, c.uri or " ".join(c.argv[:6])]
                for c in cases]
        from ..ui.widgets import table

        for line in table(con, ["id", "category", "component", "case", "input"], rows):
            con.write("  " + line)
        con.write("  " + con.c(f"{len(cases)} test cases (nothing was executed)", "muted"))
        return
    ctx.invoke(scan, apks=(apk,), profile_name=profile_name, rules=rules, plugins=plugins, assetlinks=assetlinks,
               no_code=no_code, fail_on=fail_on, min_severity=min_severity, min_confidence=min_confidence,
               no_history=no_history, formats=formats, out_dir=out_dir, as_json=False, quiet=False, interactive=False,
               jobs=1, top=top, dynamic=True, authorized=authorized, serial=serial, allow_physical=allow_physical,
               install=install, adb_path=adb_path, evidence=evidence)


# ------------------------------------------------------------------------------------------------ inspect
@cli.command(help="Print APK information.")
@click.argument("apk")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def info(ctx, apk, as_json):
    from ..apk import open_apk

    with open_apk(apk) as a:
        data = a.info()
    if as_json:
        click.echo(json.dumps(data, indent=2))
        return
    con = _con(ctx)
    from ..ui.widgets import box, kv

    sig = data["signing"]
    lines = kv(con, [("Package", con.c(data["package"], "white", bold=True)), ("Version", f"{data['version_name']} ({data['version_code']})"),
                     ("SDK", f"min {data['min_sdk']} target {data['target_sdk']}"), ("Size", f"{data['size']:,} bytes"),
                     ("SHA-256", data["hashes"]["sha256"]), ("SHA-1", data["hashes"]["sha1"]), ("MD5", data["hashes"]["md5"]),
                     ("DEX", ", ".join(data["dex_files"]) or "none"), ("ABIs", ", ".join(data["native_abis"]) or "none"),
                     ("Signing", ", ".join(k for k, v in sig["schemes"].items() if v) or "unsigned")], 10)
    for c in sig["certificates"]:
        lines.append(con.c("Signer".ljust(10), "muted") + f"{c['subject']}  ({c['key_type']} {c['key_bits']}, until {c['not_after'][:10]})")
    for l in box(con, lines, data["file_name"], min(con.width, 110)):
        con.write("  " + l)


@cli.command(help="Print the decoded AndroidManifest.xml.")
@click.argument("apk")
def manifest(apk):
    from ..apk import open_apk

    with open_apk(apk) as a:
        click.echo(a.manifest_xml())


@cli.command(help="List the deep links and exported entry points of an APK.")
@click.argument("apk")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def links(ctx, apk, as_json):
    from ..analysis import analyze_apk

    res = analyze_apk(apk, Profile(code_analysis=False))
    if as_json:
        click.echo(json.dumps({"deep_links": [l.to_dict() for l in res.deep_links],
                               "entry_points": [e.to_dict() for e in res.entry_points]}, indent=2))
        return
    con = _con(ctx)
    d = {"deep_links": [l.to_dict() for l in res.deep_links], "entry_points": [e.to_dict() for e in res.entry_points]}
    con.write("")
    views.print_links(con, d)
    con.write("")
    views.print_entry_points(con, d)


# ------------------------------------------------------------------------------------------------ history / findings
@cli.group(help="Local scan history.")
def history() -> None:
    pass


@history.command("list")
@click.option("-n", "--limit", default=30)
@click.option("--package", default=None)
@click.pass_context
def history_list(ctx, limit, package):
    views.print_history(_con(ctx), Store().list_scans(limit, package))


@history.command("show")
@click.argument("scan_id", type=int)
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def history_show(ctx, scan_id, as_json):
    st = Store()
    rep = _overlay(st, st.get_scan(scan_id))
    if as_json:
        click.echo(json.dumps(rep, indent=2))
    else:
        views.print_summary(_con(ctx), rep, 25)


@history.command("diff")
@click.argument("old_id", type=int)
@click.argument("new_id", type=int)
@click.pass_context
def history_diff(ctx, old_id, new_id):
    st = Store()
    d = st.diff(st.get_scan(old_id), st.get_scan(new_id))
    con = _con(ctx)
    con.write(f"  risk {d['risk_before']} → {d['risk_after']}")
    for label, color, items in (("NEW", "bad", d["new"]), ("RESOLVED", "ok", d["resolved"])):
        con.write("")
        con.write("  " + con.c(f"{label} ({len(items)})", color, bold=True))
        for f in items:
            con.write(f"   {con.sev(f['severity'][:4])} {f['title']} {con.c(f.get('component') or 'app', 'dim')}")


@history.command("delete")
@click.argument("scan_id", type=int)
def history_delete(scan_id):
    if not Store().delete_scan(scan_id):
        raise DlxError(f"scan {scan_id} not found")
    click.echo(f"deleted scan {scan_id}")


@history.command("prune")
@click.option("--keep", default=50, show_default=True)
def history_prune(keep):
    click.echo(f"removed {Store().prune(keep)} scan(s)")


@cli.group(help="Finding status tracking.")
def finding() -> None:
    pass


@finding.command("list")
@click.argument("package")
@click.pass_context
def finding_list(ctx, package):
    st = Store()
    rep = st.latest(package)
    if not rep:
        raise DlxError(f"no scan recorded for {package}")
    _overlay(st, rep)
    con = _con(ctx)
    from ..ui.widgets import table

    rows = [[con.c(f["id"], "muted"), con.sev(f["severity"][:4]), f["title"], f["status"], con.c(f["fingerprint"], "dim")]
            for f in rep["findings"]]
    for l in table(con, ["id", "sev", "finding", "status", "fingerprint"], rows):
        con.write("  " + l)


@finding.command("show")
@click.argument("package")
@click.argument("finding_id")
@click.pass_context
def finding_show(ctx, package, finding_id):
    st = Store()
    rep = st.latest(package)
    if not rep:
        raise DlxError(f"no scan recorded for {package}")
    _overlay(st, rep)
    match = [f for f in rep["findings"] if f["id"].lower() == finding_id.lower() or f["fingerprint"].startswith(finding_id)]
    if len(match) != 1:
        raise DlxError(f"finding '{finding_id}' not found or ambiguous")
    views.print_finding(_con(ctx), match[0])


@finding.command("set-status", help="Set open / confirmed / false_positive / accepted / fixed.")
@click.argument("package")
@click.argument("finding_id")
@click.argument("status")
@click.option("--note", default="")
def finding_status(package, finding_id, status, note):
    fps = Store().set_status(package, finding_id, status, note)
    click.echo(f"{fps[0]} -> {status}")


@cli.command(help="Re-render reports from a recorded scan.")
@click.argument("scan_id", type=int)
@click.option("-f", "--formats", default="html")
@click.option("-o", "--out", "out_dir", default="deeplinkx-reports")
@click.pass_context
def report(ctx, scan_id, formats, out_dir):
    st = Store()
    rep = _overlay(st, st.get_scan(scan_id))
    con = _con(ctx)
    for p in write_reports(rep, out_dir, [f.strip() for f in formats.split(",")], stem=f"deeplinkx-scan-{scan_id}"):
        con.write(f"  {con.c('›', 'teal')} {p}")


@cli.command(help="Interactive findings browser for a recorded scan or an APK.")
@click.argument("target")
@click.pass_context
def browse(ctx, target):
    con = _con(ctx)
    if not (con.is_tty and sys.stdin.isatty()):
        raise DlxError("browse needs an interactive terminal")
    store = Store()
    if target.isdigit():
        rep = store.get_scan(int(target))
    else:
        rep = run_scan(target, "standard", store=store).to_dict()
    pkg = rep["apk"]["package"]
    from ..ui.browser import FindingsBrowser

    FindingsBrowser(con, rep, lambda f, s: store.set_status(pkg, f["id"], s)).run()


# ------------------------------------------------------------------------------------------------ rules / profiles / plugins
@cli.group(help="Security rules.")
def rules() -> None:
    pass


@rules.command("list")
@click.option("--rules", "rule_files", multiple=True, type=click.Path())
@click.option("--plugins", "plugin_dirs", multiple=True, type=click.Path())
@click.option("--category", default=None)
@click.pass_context
def rules_list(ctx, rule_files, plugin_dirs, category):
    reg = build_registry(Profile(rule_files=list(rule_files), plugin_dirs=list(plugin_dirs)))
    norm = lambda t: t.lower().replace(" ", "").replace("-", "")
    items = [r for r in reg.rules if not category or norm(r.meta.category) == norm(category)]
    con = _con(ctx)
    views.print_rules(con, items)
    con.write("  " + con.c(f"{len(items)} rules", "muted"))
    for e in reg.errors:
        con.write("  " + con.c("error: ", "warn") + e)


@rules.command("show")
@click.argument("rule_id")
@click.pass_context
def rules_show(ctx, rule_id):
    reg = build_registry(Profile())
    r = reg.get(rule_id.upper())
    if not r:
        raise DlxError(f"unknown rule {rule_id}")
    con = _con(ctx)
    m = r.meta
    from ..ui.term import wrap

    con.write("")
    con.write(f"  {con.sev(m.severity.name)} {con.c(m.id, 'teal', bold=True)} {con.c(m.title, 'white', bold=True)}")
    con.write(f"  {con.c(m.category + ' · confidence ' + m.confidence.name.lower() + ' · ' + m.source, 'dim')}")
    for title, text in (("Description", m.description), ("Impact", m.impact), ("Remediation", m.remediation)):
        if text:
            con.write("")
            con.write("  " + con.c(title.upper(), "muted", bold=True))
            for l in wrap(text, min(con.width, 100) - 4):
                con.write("  " + l)


@rules.command("validate", help="Validate a YAML rule file.")
@click.argument("path", type=click.Path(exists=True))
def rules_validate(path):
    from ..rules.yaml_rules import load_yaml_rules

    loaded = load_yaml_rules(path)
    click.echo(f"{path}: {len(loaded)} rule(s) OK ({', '.join(r.id for r in loaded)})")


@cli.group(help="Scan profiles.")
def profiles() -> None:
    pass


@profiles.command("list")
@click.pass_context
def profiles_list(ctx):
    con = _con(ctx)
    for n in list_profiles():
        p = load_profile(n)
        con.write(f"  {con.c(n.ljust(10), 'teal', bold=True)} {p.description}")


@profiles.command("show")
@click.argument("name")
def profiles_show(name):
    click.echo(json.dumps(load_profile(name).to_dict(), indent=2))


@cli.group(help="Plugins.")
def plugins() -> None:
    pass


@plugins.command("list")
@click.option("--plugins", "plugin_dirs", multiple=True, type=click.Path())
@click.pass_context
def plugins_list(ctx, plugin_dirs):
    reg = build_registry(Profile(plugin_dirs=list(plugin_dirs)))
    con = _con(ctx)
    con.write(f"  plugin directory: {home_dir() / 'plugins'}")
    for p in reg.plugins:
        con.write(f"  {con.c('●', 'ok')} {p}")
    if not reg.plugins:
        con.write("  " + con.c("no plugins loaded", "muted"))
    for e in reg.errors:
        con.write("  " + con.c("error: ", "warn") + e)


# ------------------------------------------------------------------------------------------------ environment
@cli.command(help="Check the local environment (dependencies, adb, emulator).")
@click.pass_context
def doctor(ctx):
    import importlib

    con = _con(ctx)
    rows = []

    def add(name: str, ok: bool, detail: str, required: bool = True):
        mark = con.c("✔", "ok", bold=True) if ok else con.c("✖" if required else "–", "bad" if required else "warn", bold=True)
        rows.append([name, mark, detail])

    add("python", sys.version_info >= (3, 9), platform.python_version())
    for mod in ("click", "yaml", "jinja2", "cryptography", "reportlab", "starlette", "uvicorn", "sse_starlette"):
        try:
            importlib.import_module(mod)
            from importlib import metadata

            try:
                ver = metadata.version({"yaml": "PyYAML", "jinja2": "Jinja2", "sse_starlette": "sse-starlette"}.get(mod, mod))
            except metadata.PackageNotFoundError:
                ver = "installed"
            add(mod, True, ver)
        except ImportError:
            add(mod, False, "missing: pip install deeplinkx")
    try:
        import androguard  # noqa: F401

        add("androguard", True, "installed (optional)", False)
    except ImportError:
        add("androguard", False, "not installed (optional, built-in parsers are used)", False)
    from ..dynamic.adb import find_adb
    from ..dynamic.emulator import find_emulator

    for label, finder in (("adb", find_adb), ("emulator", find_emulator)):
        try:
            add(label, True, finder(), False)
        except DeeplinkXError as exc:
            add(label, False, str(exc).split(".")[0], False)
    try:
        h = home_dir()
        add("data dir", os.access(h, os.W_OK), str(h))
    except OSError as exc:
        add("data dir", False, str(exc))
    from ..ui.widgets import table

    for l in table(con, ["check", "", "detail"], rows):
        con.write("  " + l)


@cli.command(help="Start the REST API and web dashboard.")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8787, show_default=True)
@click.option("--token", default=None, help="Require this bearer token (or set DEEPLINKX_API_TOKEN).")
@click.option("--open", "open_browser", is_flag=True, help="Open the dashboard in the default browser.")
@click.pass_context
def serve(ctx, host, port, token, open_browser):
    if token:
        os.environ["DEEPLINKX_API_TOKEN"] = token
    from ..api.server import run_server

    con = _con(ctx)
    show_banner(con, compact=True, animated=False)
    if host not in ("127.0.0.1", "localhost", "::1") and not os.environ.get("DEEPLINKX_API_TOKEN"):
        con.write("  " + con.c("warning: ", "warn", bold=True) + "listening on a non-local address without a token. "
                  "Set --token or DEEPLINKX_API_TOKEN.")
    con.write(f"  dashboard  {con.c(f'http://{host}:{port}/', 'teal', bold=True)}")
    con.write(f"  api docs   {con.c(f'http://{host}:{port}/api/v1', 'dim')}")
    if open_browser:
        import webbrowser

        webbrowser.open(f"http://{host}:{port}/")
    run_server(host, port)


@cli.group(help="Android emulator helpers.")
def emulator() -> None:
    pass


@emulator.command("list")
def emulator_list():
    from ..dynamic.emulator import list_avds

    for a in list_avds():
        click.echo(a)


@emulator.command("start")
@click.argument("avd")
@click.option("--port", default=5554)
@click.option("--window", is_flag=True, help="Show the emulator window (default is headless).")
@click.option("--adb", "adb_path", default=None)
def emulator_start(avd, port, window, adb_path):
    from ..dynamic import Adb, SafetyPolicy
    from ..dynamic.emulator import start_emulator

    start_emulator(avd, port, headless=not window)
    adb = Adb(adb_path, serial=f"emulator-{port}", policy=SafetyPolicy())
    click.echo(f"booting {avd} on emulator-{port} ...")
    if not adb.wait_boot():
        raise DlxError("emulator did not finish booting in time")
    click.echo("ready")


@emulator.command("stop")
@click.option("--serial", default="emulator-5554")
@click.option("--adb", "adb_path", default=None)
def emulator_stop(serial, adb_path):
    from ..dynamic import Adb, SafetyPolicy
    from ..dynamic.emulator import stop_emulator

    stop_emulator(Adb(adb_path, serial=serial, policy=SafetyPolicy()))
    click.echo("stopped")


def main(argv: Optional[list[str]] = None) -> None:
    try:
        rv = cli.main(args=argv, prog_name="deeplinkx", standalone_mode=False)
        if isinstance(rv, int) and rv:
            sys.exit(rv)
    except click.exceptions.Exit as exc:
        sys.exit(exc.exit_code)
    except click.ClickException as exc:
        exc.show()
        sys.exit(exc.exit_code)
    except click.Abort:
        sys.stderr.write("aborted\n")
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)
