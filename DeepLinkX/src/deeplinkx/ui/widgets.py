from __future__ import annotations

from typing import Iterable, Optional, Sequence

from .term import Console, pad, strip_ansi, truncate, visible_len, wrap

BAR_FULL = "█"
BAR_PARTS = " ▏▎▍▌▋▊▉"
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_ICON = {"CRITICAL": "●", "HIGH": "●", "MEDIUM": "●", "LOW": "●", "INFO": "●"}


def bar(con: Console, fraction: float, width: int, color: str = "teal", end_color: Optional[str] = "violet",
        track: str = "dim") -> str:
    fraction = min(max(fraction, 0.0), 1.0)
    if not con.unicode:
        filled = int(round(fraction * width))
        return "[" + "#" * filled + "." * (width - filled) + "]"
    total = fraction * width
    full = int(total)
    part = int((total - full) * 8)
    body = BAR_FULL * full + (BAR_PARTS[part] if part and full < width else "")
    rest = max(width - visible_len(body), 0)
    colored = con.gradient(body, color, end_color) if end_color else con.c(body, color)
    return colored + con.c("░" * rest, track, dim=True)


def box(con: Console, lines: Sequence[str], title: str = "", width: Optional[int] = None, color: str = "dim",
        title_color: str = "teal") -> list[str]:
    w = width or con.width
    inner = w - 4
    if con.unicode:
        tl, tr, bl, br, h, v = "╭", "╮", "╰", "╯", "─", "│"
    else:
        tl = tr = bl = br = "+"
        h, v = "-", "|"
    out = []
    if title:
        t = f" {title} "
        out.append(con.c(tl + h, color) + con.c(t, title_color, bold=True) + con.c(h * max(w - 3 - len(t), 0) + tr, color))
    else:
        out.append(con.c(tl + h * (w - 2) + tr, color))
    for line in lines:
        line = truncate(line, inner)
        out.append(con.c(v, color) + " " + pad(line, inner) + " " + con.c(v, color))
    out.append(con.c(bl + h * (w - 2) + br, color))
    return out


def table(con: Console, headers: Sequence[str], rows: Sequence[Sequence[str]], widths: Optional[Sequence[int]] = None,
          max_width: Optional[int] = None, aligns: Optional[Sequence[str]] = None) -> list[str]:
    """Box drawn table; flexible columns shrink to fit `max_width`."""
    max_width = max_width or con.width
    ncol = len(headers)
    natural = [max([visible_len(headers[i])] + [visible_len(r[i]) for r in rows]) for i in range(ncol)]
    cols = list(widths) if widths else natural[:]
    overhead = 3 * ncol + 1
    budget = max_width - overhead
    while sum(cols) > budget:
        i = cols.index(max(cols))
        if cols[i] <= 6:
            break
        cols[i] -= 1
    aligns = aligns or ["left"] * ncol
    if con.unicode:
        h, v, tl, tm, tr, ml, mm, mr, bl, bm, br = "─", "│", "┌", "┬", "┐", "├", "┼", "┤", "└", "┴", "┘"
    else:
        h, v, tl, tm, tr, ml, mm, mr, bl, bm, br = "-", "|", "+", "+", "+", "+", "+", "+", "+", "+", "+"

    def line(l, m, r):
        return con.c(l + m.join(h * (c + 2) for c in cols) + r, "dim")

    def row(cells, head=False):
        parts = []
        for i, cell in enumerate(cells):
            txt = truncate(str(cell), cols[i])
            if head:
                txt = con.c(strip_ansi(txt).upper(), "muted", bold=True)
            parts.append(" " + pad(txt, cols[i], aligns[i]) + " ")
        sep = con.c(v, "dim")
        return sep + sep.join(parts) + sep

    out = [line(tl, tm, tr), row(headers, True), line(ml, mm, mr)]
    out += [row(r) for r in rows]
    out.append(line(bl, bm, br))
    return out


def kv(con: Console, pairs: Iterable[tuple[str, str]], key_width: int = 14) -> list[str]:
    return [con.c(pad(k, key_width), "muted") + v for k, v in pairs]


def gauge(con: Console, value: int, width: int = 30) -> str:
    color = "critical" if value >= 75 else "high" if value >= 50 else "medium" if value >= 25 else "low"
    filled = bar(con, value / 100, width, color, color)
    return f"{filled} {con.c(str(value), color, bold=True)}{con.c('/100', 'muted')}"


def sev_bars(con: Console, counts: dict[str, int], width: int = 28) -> list[str]:
    top = max(list(counts.values()) + [1])
    lines = []
    for s in SEV_ORDER:
        n = counts.get(s, 0)
        key = s.lower()
        lines.append(con.c(SEV_ICON[s] + " ", key) + con.c(pad(s.title(), 9), "white") +
                     bar(con, n / top if n else 0, width, key, key) + " " + con.c(str(n), key if n else "dim", bold=True))
    return lines


def sparkline(con: Console, values: Sequence[float]) -> str:
    ticks = "▁▂▃▄▅▆▇█"
    if not values:
        return ""
    hi = max(values) or 1
    return con.gradient("".join(ticks[min(int(v / hi * 7), 7)] for v in values))


def badge(con: Console, text: str, color: str) -> str:
    return con.c(f" {text} ", "panel" if color in ("white",) else "white", bold=True, bg=color) if con.mode != "none" else f"[{text}]"


def wrap_lines(con: Console, text: str, width: int, indent: str = "") -> list[str]:
    return [indent + l for l in wrap(text, max(width - len(indent), 10))]
