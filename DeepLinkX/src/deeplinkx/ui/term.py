"""Minimal ANSI terminal toolkit (no third party UI library): colour modes, styles, width handling, cursor control."""
from __future__ import annotations

import os
import re
import shutil
import sys
import threading
import unicodedata
from typing import IO, Optional

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
ESC = "\x1b"

PALETTE = {
    "teal": (79, 209, 197), "violet": (124, 140, 255), "white": (231, 236, 248), "muted": (141, 155, 189),
    "dim": (92, 105, 140), "critical": (255, 59, 92), "high": (255, 122, 69), "medium": (245, 182, 56),
    "low": (63, 184, 165), "info": (107, 140, 255), "ok": (74, 222, 128), "bad": (255, 59, 92),
    "warn": (245, 182, 56), "panel": (22, 33, 58),
}


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def cell_width(ch: str) -> int:
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def visible_len(text: str) -> int:
    return sum(cell_width(c) for c in strip_ansi(text))


def truncate(text: str, width: int, ellipsis: str = "…") -> str:
    """Truncate to `width` printable cells while keeping ANSI sequences intact."""
    if visible_len(text) <= width:
        return text
    out, used, i = [], 0, 0
    limit = max(width - 1, 0)
    while i < len(text) and used < limit:
        m = ANSI_RE.match(text, i)
        if m:
            out.append(m.group())
            i = m.end()
            continue
        w = cell_width(text[i])
        if used + w > limit:
            break
        out.append(text[i])
        used += w
        i += 1
    return "".join(out) + ellipsis + (f"{ESC}[0m" if ESC in text else "")


def pad(text: str, width: int, align: str = "left") -> str:
    gap = max(width - visible_len(text), 0)
    if align == "right":
        return " " * gap + text
    if align == "center":
        return " " * (gap // 2) + text + " " * (gap - gap // 2)
    return text + " " * gap


def wrap(text: str, width: int) -> list[str]:
    lines: list[str] = []
    for para in str(text).splitlines() or [""]:
        cur = ""
        for word in para.split(" "):
            if visible_len(cur) + visible_len(word) + (1 if cur else 0) > width and cur:
                lines.append(cur)
                cur = word
            else:
                cur = f"{cur} {word}" if cur else word
            while visible_len(cur) > width:
                lines.append(cur[:width])
                cur = cur[width:]
        lines.append(cur)
    return lines


class Console:
    """Colour aware writer. `mode` is 'truecolor', '256' or 'none'."""

    def __init__(self, stream: Optional[IO[str]] = None, force_color: Optional[bool] = None, animate: Optional[bool] = None,
                 width: Optional[int] = None):
        self.stream = stream or sys.stdout
        self.lock = threading.RLock()
        tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self.is_tty = tty
        env_no_color = "NO_COLOR" in os.environ
        if force_color is None:
            force_color = os.environ.get("FORCE_COLOR") not in (None, "", "0")
        dumb = os.environ.get("TERM") == "dumb"
        use_color = (tty and not dumb and not env_no_color) or (force_color and not env_no_color)
        if not use_color:
            self.mode = "none"
        elif os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit") or os.environ.get("WT_SESSION"):
            self.mode = "truecolor"
        else:
            self.mode = "256"
        self.animate = (tty and not dumb) if animate is None else animate
        self.fixed_width = width
        self.cursor_hidden = False

    # ---- geometry
    @property
    def width(self) -> int:
        if self.fixed_width:
            return self.fixed_width
        return max(40, min(shutil.get_terminal_size((100, 30)).columns, 200))

    @property
    def height(self) -> int:
        return shutil.get_terminal_size((100, 30)).lines

    @property
    def unicode(self) -> bool:
        enc = (getattr(self.stream, "encoding", "") or "").lower()
        return "utf" in enc

    # ---- colour
    def _fg(self, rgb: tuple[int, int, int]) -> str:
        if self.mode == "none":
            return ""
        r, g, b = rgb
        if self.mode == "truecolor":
            return f"{ESC}[38;2;{r};{g};{b}m"
        return f"{ESC}[38;5;{_to256(r, g, b)}m"

    def _bg(self, rgb: tuple[int, int, int]) -> str:
        if self.mode == "none":
            return ""
        r, g, b = rgb
        if self.mode == "truecolor":
            return f"{ESC}[48;2;{r};{g};{b}m"
        return f"{ESC}[48;5;{_to256(r, g, b)}m"

    def c(self, text: str, color: str | tuple = "white", bold: bool = False, dim: bool = False, bg: Optional[str] = None,
          italic: bool = False, underline: bool = False) -> str:
        if self.mode == "none":
            return str(text)
        rgb = PALETTE[color] if isinstance(color, str) else color
        pre = self._fg(rgb)
        if bg:
            pre += self._bg(PALETTE[bg] if isinstance(bg, str) else bg)
        if bold:
            pre += f"{ESC}[1m"
        if dim:
            pre += f"{ESC}[2m"
        if italic:
            pre += f"{ESC}[3m"
        if underline:
            pre += f"{ESC}[4m"
        return f"{pre}{text}{ESC}[0m"

    def gradient(self, text: str, start: str | tuple = "teal", end: str | tuple = "violet", bold: bool = False) -> str:
        if self.mode == "none" or not text:
            return text
        a = PALETTE[start] if isinstance(start, str) else start
        b = PALETTE[end] if isinstance(end, str) else end
        n = max(len(text) - 1, 1)
        out = []
        for i, ch in enumerate(text):
            if ch == " ":
                out.append(ch)
                continue
            t = i / n
            rgb = tuple(int(a[k] + (b[k] - a[k]) * t) for k in range(3))
            out.append(self._fg(rgb) + ("\x1b[1m" if bold else "") + ch)
        return "".join(out) + f"{ESC}[0m"

    def sev(self, severity: str, text: Optional[str] = None, bold: bool = True) -> str:
        key = severity.lower()
        return self.c(text if text is not None else severity.upper(), key if key in PALETTE else "info", bold=bold)

    # ---- output
    def write(self, text: str = "", end: str = "\n") -> None:
        with self.lock:
            self.stream.write(text + end)
            self.stream.flush()

    def print(self, *parts: str, sep: str = " ", end: str = "\n") -> None:
        self.write(sep.join(str(p) for p in parts), end)

    def raw(self, seq: str) -> None:
        if self.is_tty:
            with self.lock:
                self.stream.write(seq)
                self.stream.flush()

    def hide_cursor(self) -> None:
        if self.is_tty and not self.cursor_hidden:
            self.raw(f"{ESC}[?25l")
            self.cursor_hidden = True

    def show_cursor(self) -> None:
        if self.is_tty and self.cursor_hidden:
            self.raw(f"{ESC}[?25h")
            self.cursor_hidden = False

    def rule(self, title: str = "", color: str = "dim") -> None:
        ch = "─" if self.unicode else "-"
        w = self.width
        if title:
            t = f" {title} "
            left = 3
            self.write(self.c(ch * left, color) + self.c(t, "muted", bold=True) + self.c(ch * max(w - left - len(t), 0), color))
        else:
            self.write(self.c(ch * w, color))


def _to256(r: int, g: int, b: int) -> int:
    if abs(r - g) < 10 and abs(g - b) < 10:
        gray = round((r - 8) / 247 * 24) if r > 8 else 0
        return 232 + min(max(gray, 0), 23) if 8 < r < 248 else (16 if r <= 8 else 231)
    return 16 + 36 * round(r / 255 * 5) + 6 * round(g / 255 * 5) + round(b / 255 * 5)
