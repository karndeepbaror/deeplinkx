"""Turns raw adb output and logcat text into an observation about how the app reacted."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .testcases import CANARY_HOST

EXC_RE = re.compile(r"\b((?:[a-z][\w]*\.)+[A-Z]\w*(?:Exception|Error))\b")
NOT_FOUND = ("Error type 3", "does not exist", "unable to resolve Intent", "No activity found",
             "Activity class {", "Error: Activity not started")
DENIED = ("Permission Denial", "SecurityException", "requires", "not exported", "Requires permission")


@dataclass
class Observation:
    outcome: str = "unknown"  # launched | denied | not_found | crash | anr | data_returned | provider_error | empty | error | timeout
    resolved: str = ""
    focus: str = ""
    exceptions: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    total_time_ms: int | None = None

    def to_dict(self) -> dict:
        return {"outcome": self.outcome, "resolved": self.resolved, "focus": self.focus,
                "exceptions": self.exceptions, "flags": self.flags, "total_time_ms": self.total_time_ms}


def app_log_lines(logcat: str, package: str) -> str:
    """Lines that belong to the app: its package name or crash/ANR frames that mention it."""
    return "\n".join(l for l in logcat.splitlines() if package in l or "FATAL EXCEPTION" in l or "AndroidRuntime" in l)


def observe(case, stdout: str, stderr: str, returncode: int, timed_out: bool, logcat: str, focus: str,
            package: str) -> Observation:
    obs = Observation(focus=focus)
    out = f"{stdout}\n{stderr}"
    mine = app_log_lines(logcat, package)
    m = re.search(r"Activity: ([\w.]+/[\w.$]+)", out)
    if m:
        obs.resolved = m.group(1)
    m = re.search(r"TotalTime: (\d+)", out)
    if m:
        obs.total_time_ms = int(m.group(1))
    obs.exceptions = sorted({e for e in EXC_RE.findall(mine + "\n" + out)})
    if CANARY_HOST in logcat or "dlx_canary" in mine:
        obs.flags.append("canary_in_logs")
    if CANARY_HOST in logcat and re.search(r"(?i)(loadurl|loading|navigat|chromium|webview|http)", logcat):
        obs.flags.append("canary_url_loaded")
    if "StrictMode" in mine:
        obs.flags.append("strictmode")
    if "android.database.sqlite" in mine or "SQLiteException" in out or "SQLiteException" in mine:
        obs.flags.append("sql_error")
    if re.search(r"(?i)(no such file|FileNotFound|ENOENT|open failed)", mine + out):
        obs.flags.append("file_error")
    if timed_out:
        obs.outcome = "timeout"
    elif "FATAL EXCEPTION" in logcat and (package in logcat):
        obs.outcome = "crash"
    elif re.search(r"ANR in " + re.escape(package), logcat):
        obs.outcome = "anr"
    elif any(k in out for k in DENIED) and ("Permission Denial" in out or "SecurityException" in out
                                           or "not exported" in out):
        obs.outcome = "denied"
    elif any(k in out for k in NOT_FOUND) and "Status: ok" not in out:
        obs.outcome = "not_found"
    elif case.kind == "provider":
        if "Row:" in out:
            obs.outcome = "data_returned"
        elif "SQLiteException" in out or "Error while accessing provider" in out or "sql_error" in obs.flags:
            obs.outcome = "provider_error"
        elif "No result found" in out:
            obs.outcome = "empty"
        elif returncode == 0 and not out.strip():
            obs.outcome = "empty"
        else:
            obs.outcome = "error"
    elif "Status: ok" in out or "Starting: Intent" in out or "Starting service" in out or \
            "Broadcast completed" in out or "Starting: Intent" in out:
        obs.outcome = "launched"
        if "Error" in out and "Status: ok" not in out and "Broadcast completed" not in out:
            obs.outcome = "error"
    elif returncode != 0:
        obs.outcome = "error"
    else:
        obs.outcome = "launched" if package in focus else "unknown"
    return obs
