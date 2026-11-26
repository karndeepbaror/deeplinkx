"""Interactive full-screen findings browser (termios based, no external libraries)."""
from __future__ import annotations

import os
import select
import sys
from typing import Optional

from .term import ESC, Console, pad, truncate
from .views import finding_detail_lines

try:  # POSIX only; the browser is simply unavailable on other platforms
    import termios
    import tty
except ImportError:  # pragma: no cover
    termios = tty = None  # type: ignore[assignment]

SEV_CYCLE = [None, "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def read_key(fd: int, timeout: float = 0.5) -> Optional[str]:
    r, _, _ = select.select([fd], [], [], timeout)
    if not r:
        return None
    data = os.read(fd, 8)
    if data.startswith(b"\x1b["):
        return {b"A": "up", b"B": "down", b"C": "right", b"D": "left", b"5": "pgup", b"6": "pgdn", b"H": "home",
                b"F": "end"}.get(data[2:3], "esc")
    if data == b"\x1b":
        return "esc"
    if data in (b"\r", b"\n"):
        return "enter"
    if data == b"\x03":
        return "q"
    try:
        return data.decode()
    except UnicodeDecodeError:
        return None


class FindingsBrowser:
    def __init__(self, con: Console, report: dict, status_cb=None):
        self.con = con
        self.report = report
        self.all = report["findings"]
        self.sev_filter: Optional[str] = None
        self.query = ""
        self.sel = 0
        self.top = 0
        self.detail = False
        self.scroll = 0
        self.searching = False
        self.status_cb = status_cb
        self.message = ""

    # ---- data
    def items(self) -> list[dict]:
        out = self.all
        if self.sev_filter:
            out = [f for f in out if f["severity"] == self.sev_filter]
        if self.query:
            q = self.query.lower()
            out = [f for f in out if q in (f["title"] + f["rule_id"] + (f.get("component") or "") + f["category"]).lower()]
        return out

    # ---- drawing
    def frame(self) -> str:
        c = self.con
        h, w = c.height, c.width
        items = self.items()
        self.sel = min(self.sel, max(len(items) - 1, 0))
        head = c.gradient(" DEEPLINK X ", "teal", "violet", bold=True) + c.c(
            f" {self.report['apk']['package']}", "white", bold=True) + c.c(
            f"   {len(items)}/{len(self.all)} findings  filter: {self.sev_filter or 'all'}"
            + (f"  search: {self.query}" if self.query or self.searching else ""), "muted")
        lines = [truncate(head, w)]
        body_h = h - 3
        if self.detail and items:
            det = finding_detail_lines(c, items[self.sel], w)
            self.scroll = max(0, min(self.scroll, max(len(det) - body_h, 0)))
            lines += [truncate(l, w) for l in det[self.scroll:self.scroll + body_h]]
            foot = "↑/↓ scroll   esc back   n/p next/prev   q quit"
        else:
            if self.sel < self.top:
                self.top = self.sel
            if self.sel >= self.top + body_h:
                self.top = self.sel - body_h + 1
            for i in range(self.top, min(self.top + body_h, len(items))):
                f = items[i]
                sev = c.sev(f["severity"][:4] if f["severity"] != "MEDIUM" else "MED")
                row = f" {c.c(f['id'], 'muted')} {sev} {f['title']}  {c.c((f.get('component') or 'app').rsplit('.', 1)[-1], 'teal')}"
                if i == self.sel:
                    row = c.c("▌", "teal", bold=True) + c.c(" " + f["id"] + " ", "white", bold=True) + sev + " " + c.c(
                        f["title"], "white", bold=True) + "  " + c.c((f.get("component") or "app").rsplit(".", 1)[-1], "teal")
                    lines.append(pad(truncate(row, w), w))
                else:
                    lines.append(truncate(" " + row, w))
            if not items:
                lines.append(c.c("  no findings match", "muted"))
            foot = "↑/↓ move   enter open   f filter severity   / search   c confirm  x false-positive  a accept   q quit"
        while len(lines) < h - 1:
            lines.append("")
        status = c.c(self.message, "warn") if self.message else c.c(foot, "dim")
        lines = lines[:h - 1] + [truncate(status, w)]
        return f"{ESC}[H" + "\n".join(f"{ESC}[2K{l}" for l in lines)

    # ---- loop
    def run(self, fd_in: Optional[int] = None) -> None:
        if termios is None or not (self.con.is_tty or fd_in is not None):
            raise RuntimeError("the interactive browser needs a terminal")
        fd = fd_in if fd_in is not None else sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            self.con.raw(f"{ESC}[?1049h{ESC}[?25l")
            while True:
                self.con.raw(self.frame())
                key = read_key(fd, 1.0)
                if key is None:
                    continue
                if self.searching:
                    if key in ("enter", "esc"):
                        self.searching = False
                    elif key in ("\x7f", "\b"):
                        self.query = self.query[:-1]
                    elif len(key) == 1 and key.isprintable():
                        self.query += key
                    self.sel = 0
                    continue
                if self.handle(key):
                    break
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            self.con.raw(f"{ESC}[?25h{ESC}[?1049l")

    def handle(self, key: str) -> bool:
        items = self.items()
        self.message = ""
        if key == "q":
            return True
        if self.detail:
            if key in ("esc", "left", "b"):
                self.detail = False
            elif key in ("down", "j"):
                self.scroll += 1
            elif key in ("up", "k"):
                self.scroll = max(self.scroll - 1, 0)
            elif key == "pgdn":
                self.scroll += 10
            elif key == "pgup":
                self.scroll = max(self.scroll - 10, 0)
            elif key in ("n", "p"):
                self.sel = min(self.sel + 1, len(items) - 1) if key == "n" else max(self.sel - 1, 0)
                self.scroll = 0
            return False
        if key in ("down", "j"):
            self.sel = min(self.sel + 1, max(len(items) - 1, 0))
        elif key in ("up", "k"):
            self.sel = max(self.sel - 1, 0)
        elif key == "pgdn":
            self.sel = min(self.sel + 10, max(len(items) - 1, 0))
        elif key == "pgup":
            self.sel = max(self.sel - 10, 0)
        elif key == "home":
            self.sel = 0
        elif key == "end":
            self.sel = max(len(items) - 1, 0)
        elif key in ("enter", "right") and items:
            self.detail = True
            self.scroll = 0
        elif key == "f":
            self.sev_filter = SEV_CYCLE[(SEV_CYCLE.index(self.sev_filter) + 1) % len(SEV_CYCLE)]
            self.sel = 0
        elif key == "/":
            self.searching = True
            self.query = ""
        elif key in ("c", "x", "a", "o") and items and self.status_cb:
            status = {"c": "confirmed", "x": "false_positive", "a": "accepted", "o": "open"}[key]
            f = items[self.sel]
            try:
                self.status_cb(f, status)
                f["status"] = status
                self.message = f"{f['id']} marked {status}"
            except Exception as exc:
                self.message = f"could not update status: {exc}"
        return False
