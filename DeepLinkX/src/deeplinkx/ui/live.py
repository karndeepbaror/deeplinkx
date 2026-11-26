"""Live, animated progress for the scan pipeline (falls back to plain log lines when not a TTY)."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from .term import ESC, Console, pad, truncate, visible_len
from .widgets import SPINNER, bar

STAGES = [
    ("open", "Opening archive"),
    ("manifest", "Decoding manifest"),
    ("links", "Deep link inventory"),
    ("entry", "Entry point analysis"),
    ("config", "Permissions & network config"),
    ("code", "DEX code analysis"),
    ("assetlinks", "App Link verification"),
    ("rules", "Security rules engine"),
    ("dynamic", "Dynamic testing"),
    ("done", "Finalising"),
]


@dataclass
class _Stage:
    key: str
    label: str
    state: str = "pending"  # pending | running | done | skipped
    fraction: float = 0.0
    message: str = ""
    started: float = 0.0
    elapsed: float = 0.0


class ScanDisplay:
    """Use as a context manager; call `update(stage, fraction, message)` (the scan progress callback)."""

    def __init__(self, con: Console, title: str = "", stages: Optional[list[tuple[str, str]]] = None,
                 show_dynamic: bool = False):
        self.con = con
        self.title = title
        keys = stages or [s for s in STAGES if show_dynamic or s[0] != "dynamic"]
        self.stages = {k: _Stage(k, label) for k, label in keys}
        self.order = [k for k, _ in keys]
        self._lock = threading.Lock()
        self._frame = 0
        self._drawn = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.live = con.is_tty and con.animate

    # ---- callback
    def update(self, stage: str, fraction: float, message: str = "") -> None:
        st = self.stages.get(stage)
        if st is None:
            return
        with self._lock:
            if st.state == "pending":
                st.state = "running"
                st.started = time.monotonic()
                # everything before it is finished
                for k in self.order:
                    if k == stage:
                        break
                    s = self.stages[k]
                    if s.state in ("pending", "running"):
                        s.state = "done" if s.state == "running" else "skipped"
                        s.fraction = 1.0 if s.state == "done" else 0.0
            st.fraction = max(st.fraction, fraction)
            if message:
                st.message = message
            if fraction >= 1.0 and st.state == "running":
                st.state = "done"
                st.elapsed = time.monotonic() - st.started
                if not self.live:
                    self.con.write(f"  [ok] {st.label}" + (f" - {st.message}" if st.message else ""))

    # ---- rendering
    def _render(self) -> list[str]:
        c = self.con
        spin = SPINNER[self._frame % len(SPINNER)] if c.unicode else "|/-\\"[self._frame % 4]
        lines = []
        if self.title:
            lines.append("  " + c.c(self.title, "white", bold=True))
        width = c.width
        for k in self.order:
            s = self.stages[k]
            if s.state == "done":
                icon, label = c.c("✔" if c.unicode else "+", "ok", bold=True), c.c(pad(s.label, 30), "white")
                tail = c.c(truncate(s.message, width - 52), "muted") + c.c(f"  {s.elapsed:.2f}s", "dim") if s.message else \
                    c.c(f"{s.elapsed:.2f}s", "dim")
            elif s.state == "running":
                icon, label = c.c(spin, "teal", bold=True), c.c(pad(s.label, 30), "teal", bold=True)
                tail = bar(c, s.fraction, 16) + "  " + c.c(truncate(s.message, width - 56), "muted")
            elif s.state == "skipped":
                icon, label, tail = c.c("–", "dim"), c.c(pad(s.label, 30), "dim"), c.c("skipped", "dim")
            else:
                icon, label, tail = c.c("·", "dim"), c.c(pad(s.label, 30), "dim"), ""
            lines.append(f"   {icon} {label} {tail}")
        return lines

    def _draw(self) -> None:
        with self._lock:
            lines = self._render()
            out = []
            if self._drawn:
                out.append(f"{ESC}[{self._drawn}F")
            for l in lines:
                out.append(f"{ESC}[2K{l}\n")
            self._drawn = len(lines)
        self.con.raw("".join(out))

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._frame += 1
            self._draw()
            self._stop.wait(0.08)

    def __enter__(self) -> "ScanDisplay":
        if self.live:
            self.con.hide_cursor()
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
        elif self.title:
            self.con.write(self.title)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.live:
            self._stop.set()
            if self._thread:
                self._thread.join(timeout=1)
            with self._lock:
                for s in self.stages.values():
                    if s.state == "running":
                        s.state = "done" if exc_type is None else "pending"
                        s.elapsed = time.monotonic() - s.started
            self._draw()
            self.con.show_cursor()
