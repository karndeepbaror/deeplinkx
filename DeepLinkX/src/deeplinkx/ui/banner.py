from __future__ import annotations

import time

from ..version import AUTHOR, GITHUB, TAGLINE, X_HANDLE, __version__
from .term import Console, pad, visible_len

FONT = {
    "D": ["████ ", "█   █", "█   █", "█   █", "████ "],
    "E": ["█████", "█    ", "████ ", "█    ", "█████"],
    "P": ["████ ", "█   █", "████ ", "█    ", "█    "],
    "L": ["█    ", "█    ", "█    ", "█    ", "█████"],
    "I": ["█████", "  █  ", "  █  ", "  █  ", "█████"],
    "N": ["█   █", "██  █", "█ █ █", "█  ██", "█   █"],
    "K": ["█   █", "█  █ ", "███  ", "█  █ ", "█   █"],
    "X": ["█   █", " █ █ ", "  █  ", " █ █ ", "█   █"],
}


def logo_lines(con: Console) -> list[str]:
    word = "DEEPLINK"
    rows = []
    for r in range(5):
        left = " ".join(FONT[ch][r] for ch in word)
        right = FONT["X"][r]
        if con.mode == "none":
            rows.append(left + "   " + right)
        else:
            rows.append(con.gradient(left, "teal", "violet", bold=True) + "   " + con.c(right, "critical", bold=True))
    return rows


def banner_lines(con: Console, compact: bool = False) -> list[str]:
    if compact or con.width < 64 or not con.unicode:
        title = con.gradient("DEEPLINK", "teal", "violet", bold=True) + " " + con.c("X", "critical", bold=True)
        return [f"{title}  {con.c('v' + __version__, 'muted')}", con.c(TAGLINE, "muted", italic=True)]
    lines = logo_lines(con)
    width = max(visible_len(l) for l in lines)
    tag = con.c(TAGLINE, "white", italic=True)
    sub = con.c(f"Android Deep Link Security Auditor  v{__version__}", "muted")
    lines += ["", pad(tag, width), pad(sub, width),
              con.c(f"by {AUTHOR}  ·  {GITHUB}  ·  {X_HANDLE}", "dim")]
    return lines


def show_banner(con: Console, compact: bool = False, animated: bool = True) -> None:
    lines = banner_lines(con, compact)
    con.write("")
    if animated and con.animate and con.is_tty and not compact:
        con.hide_cursor()
        try:
            for l in lines:
                con.write("  " + l)
                time.sleep(0.045)
        finally:
            con.show_cursor()
    else:
        for l in lines:
            con.write("  " + l)
    con.write("")
