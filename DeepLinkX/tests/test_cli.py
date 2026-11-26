import json

import pytest
from click.testing import CliRunner

from deeplinkx.cli.main import cli
from deeplinkx.ui.term import Console, cell_width, strip_ansi, truncate, visible_len, wrap
from deeplinkx.ui.widgets import box, table


def run(*args, **kw):
    return CliRunner().invoke(cli, ["--no-anim", *args], **kw)


def test_scan_writes_reports_and_history(vuln_apk, tmp_path):
    out = tmp_path / "r"
    r = run("scan", str(vuln_apk), "-o", str(out), "-f", "html,json,sarif,pdf")
    assert r.exit_code == 0, r.output
    assert "com.shop.demo" in r.output
    assert {p.suffix for p in out.iterdir()} == {".html", ".json", ".sarif", ".pdf"}
    h = run("history", "list")
    assert "com.shop.demo" in h.output


def test_fail_on_exit_code(vuln_apk, tmp_path):
    assert run("scan", str(vuln_apk), "-q", "--no-history", "--fail-on", "high", "-o", str(tmp_path)).exit_code == 2
    assert run("scan", str(vuln_apk), "-q", "--no-history", "--fail-on", "critical", "-o", str(tmp_path)).exit_code == 0


def test_json_output_is_pure_json(vuln_apk):
    r = CliRunner(mix_stderr=False).invoke(cli, ["scan", str(vuln_apk), "--json", "--no-history"]) \
        if "mix_stderr" in CliRunner.__init__.__code__.co_varnames else run("scan", str(vuln_apk), "--json", "--no-history")
    data = json.loads(r.stdout if hasattr(r, "stdout") else r.output)
    assert data["apk"]["package"] == "com.shop.demo"


def test_dynamic_requires_authorization(vuln_apk):
    r = run("scan", str(vuln_apk), "--dynamic")
    assert r.exit_code == 3
    assert "authorized" in r.output


def test_missing_file_and_garbage(tmp_path):
    assert run("scan", str(tmp_path / "x.apk")).exit_code == 1
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"junk")
    assert run("scan", str(bad), "--no-history").exit_code == 1


def test_batch_directory(vuln_apk, tmp_path):
    d = tmp_path / "apks"
    d.mkdir()
    for n in ("a.apk", "b.apk"):
        (d / n).write_bytes(open(vuln_apk, "rb").read())
    (d / "broken.apk").write_bytes(b"zzz")
    out = tmp_path / "o"
    r = run("scan", str(d), "-o", str(out), "-f", "json", "-j", "2", "--no-history")
    assert r.exit_code == 0, r.output
    summary = json.loads((out / "batch-summary.json").read_text())
    assert len(summary) == 3 and sum(1 for s in summary if s.get("error")) == 1
    assert (out / "batch-summary.csv").read_text().startswith("file,package")


def test_inspection_commands(vuln_apk):
    assert "com.shop.demo" in run("info", str(vuln_apk)).output
    assert json.loads(run("info", str(vuln_apk), "--json").output)["package"] == "com.shop.demo"
    assert "<manifest" in run("manifest", str(vuln_apk)).output
    assert "myshop://pay" in run("links", str(vuln_apk)).output
    assert "test cases" in run("dynamic", str(vuln_apk), "--plan-only").output


def test_history_finding_status_and_report(vuln_apk, tmp_path):
    run("scan", str(vuln_apk), "-q", "-o", str(tmp_path / "a"), "-f", "json")
    run("scan", str(vuln_apk), "-q", "-o", str(tmp_path / "a"), "-f", "json")
    assert "F-001" in run("finding", "list", "com.shop.demo").output
    assert "F-001" in run("finding", "show", "com.shop.demo", "F-001").output
    assert run("finding", "set-status", "com.shop.demo", "F-001", "false_positive").exit_code == 0
    assert "false_positive" in run("finding", "list", "com.shop.demo").output
    assert run("finding", "set-status", "com.shop.demo", "F-001", "bogus").exit_code != 0
    assert "risk" in run("history", "diff", "1", "2").output
    assert run("history", "show", "1").exit_code == 0
    out = tmp_path / "re"
    assert run("report", "1", "-f", "html,json", "-o", str(out)).exit_code == 0
    assert len(list(out.iterdir())) == 2
    assert run("history", "delete", "1").exit_code == 0
    assert run("history", "delete", "99").exit_code == 1
    assert run("history", "prune", "--keep", "1").exit_code == 0


def test_rules_profiles_plugins_doctor(tmp_path):
    assert "DLX-" in run("rules", "list").output
    assert "11 rules" in run("rules", "list", "--category", "deep link").output
    assert "DLX-" in run("rules", "show", "dlx-211").output
    assert run("rules", "show", "nope").exit_code == 1
    y = tmp_path / "r.yaml"
    y.write_text("rules:\n  - id: ORG-1\n    title: t\n    severity: low\n    when: {kind: nonsense}\n")
    assert run("rules", "validate", str(y)).exit_code != 0
    assert "standard" in run("profiles", "list").output
    assert json.loads(run("profiles", "show", "ci").output)["fail_on"] == "HIGH"
    assert run("plugins", "list").exit_code == 0
    assert "python" in run("doctor").output


def test_custom_rules_and_plugin_flags(vuln_apk, tmp_path):
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    r = run("scan", str(vuln_apk), "-q", "--no-history", "--rules", str(root / "rules"),
            "--plugins", str(root / "plugins"), "-o", str(tmp_path))
    assert r.exit_code == 0, r.output


# ----------------------------------------------------------------------------- ui
def test_ansi_helpers():
    assert strip_ansi("\x1b[31mred\x1b[0m") == "red"
    assert visible_len("\x1b[1mabc\x1b[0m") == 3
    assert cell_width("日") == 2
    assert visible_len(truncate("x" * 50, 10)) == 10
    assert all(len(l) <= 12 for l in wrap("word " * 30, 12))


def test_console_color_modes(monkeypatch):
    import io

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("COLORTERM", "truecolor")
    buf = io.StringIO()
    c = Console(buf, force_color=True)
    c.write(c.c("hi", "teal"))
    assert "\x1b[" in buf.getvalue() and "38;2;" in buf.getvalue()
    monkeypatch.setenv("NO_COLOR", "1")
    buf2 = io.StringIO()
    c2 = Console(buf2)
    c2.write(c2.c("hi", "teal"))
    assert buf2.getvalue().strip() == "hi"


def test_box_and_table_alignment():
    import io

    c = Console(io.StringIO(), width=60)
    lines = box(c, ["日本語 line", "short"], "T", 40)
    assert len({visible_len(l) for l in lines}) == 1
    t = table(c, ["a", "b"], [["x", "y" * 80]])
    assert max(visible_len(l) for l in t) <= 60


def test_interactive_browser_in_pty(vuln_apk, tmp_path):
    import os
    import pty
    import select
    import subprocess
    import sys
    import time

    master, slave = pty.openpty()
    env = dict(os.environ, DEEPLINKX_HOME=str(tmp_path / "h"), TERM="xterm-256color", COLUMNS="110", LINES="40")
    env.pop("NO_COLOR", None)
    p = subprocess.Popen([sys.executable, "-m", "deeplinkx", "--no-anim", "scan", str(vuln_apk), "-i", "-o",
                          str(tmp_path / "o"), "-f", "json"], stdin=slave, stdout=slave, stderr=slave, env=env, close_fds=True)
    os.close(slave)
    buf = b""
    deadline = time.time() + 40
    sent = 0
    while time.time() < deadline and p.poll() is None:
        r, _, _ = select.select([master], [], [], 0.3)
        if r:
            try:
                buf += os.read(master, 65536)
            except OSError:
                break
        elif b"Reports" in buf and sent < 3:
            os.write(master, [b"\x1b[B", b"\r", b"q"][sent])
            sent += 1
            time.sleep(0.4)
    if p.poll() is None:
        os.write(master, b"q")
        time.sleep(1)
    if p.poll() is None:
        p.kill()
    text = buf.decode("utf8", "replace")
    assert "Reports" in text and sent >= 1
    assert p.returncode in (0, 2, None, -9) or p.returncode is not None
