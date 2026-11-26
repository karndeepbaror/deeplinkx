"""Safety rails for the dynamic engine.

Dynamic testing sends real intents to a running app. It is limited to authorised test applications in isolated
environments: an explicit authorisation flag is mandatory, only emulators are used by default, only the package under
test is addressed, and every command is checked against an allow-list before it is executed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from ..errors import SafetyError

PKG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
SERIAL_RE = re.compile(r"^[A-Za-z0-9_.:\-]{3,64}$")

AUTH_MESSAGE = (
    "Dynamic testing sends real intents to an app on a device. It must only be used on applications you own or are "
    "explicitly authorised to test, in an isolated environment. Pass --authorized (or authorized=True) to confirm."
)

ADB_ALLOWED = {"devices", "get-state", "wait-for-device", "start-server", "shell", "install", "logcat", "exec-out",
               "emu", "version", "uninstall"}
SHELL_ALLOWED = {"am", "pm", "content", "getprop", "dumpsys", "ps", "pidof", "screencap", "input_none"}
AM_ALLOWED = {"start", "startservice", "start-foreground-service", "broadcast", "force-stop", "stack"}
PM_ALLOWED = {"path", "list"}
DUMPSYS_ALLOWED = {"window", "activity", "package"}


@dataclass
class SafetyPolicy:
    package: str = ""
    authorized: bool = False
    allow_physical: bool = False
    allow_install: bool = True
    allow_uninstall: bool = False
    max_cases: int = 400
    authorities: set[str] = field(default_factory=set)
    audit: list[str] = field(default_factory=list)

    def require_authorization(self) -> None:
        if not self.authorized:
            raise SafetyError(AUTH_MESSAGE)
        if not PKG_RE.match(self.package or ""):
            raise SafetyError(f"invalid package name: {self.package!r}")

    def check_serial(self, serial: Optional[str]) -> None:
        if serial is not None and not SERIAL_RE.match(serial):
            raise SafetyError(f"invalid device serial: {serial!r}")

    def check_device(self, serial: str, is_emulator: bool) -> None:
        if not is_emulator and not self.allow_physical:
            raise SafetyError(
                f"{serial} is not an emulator. Dynamic tests run on emulators by default; pass --allow-physical only "
                "for a dedicated, isolated test device.")

    def check_adb(self, args: list[str]) -> None:
        """Validate the arguments that follow `adb [-s serial]`."""
        if not args:
            raise SafetyError("empty adb command")
        sub = args[0]
        if sub not in ADB_ALLOWED:
            raise SafetyError(f"adb sub-command '{sub}' is not allowed")
        if sub == "uninstall" and not (self.allow_uninstall and args[-1] == self.package):
            raise SafetyError("uninstall is only allowed for the package under test and when enabled")
        if sub == "install" and not self.allow_install:
            raise SafetyError("installing packages is disabled")
        if sub == "emu" and args[1:2] != ["kill"]:
            raise SafetyError("only 'adb emu kill' is allowed")
        if sub == "exec-out" and args[1:2] != ["screencap"]:
            raise SafetyError("exec-out is only allowed for screencap")
        if sub == "shell":
            self.check_shell(args[1:])

    def check_shell(self, tokens: list[str]) -> None:
        if not tokens:
            raise SafetyError("empty shell command")
        # the device shell would interpret operators, so none of them may be present as raw tokens
        for t in tokens:
            if t in (";", "&&", "||", "|", ">", ">>", "<", "&", "`"):
                raise SafetyError(f"shell operator {t!r} is not allowed")
        cmd = tokens[0]
        if cmd not in SHELL_ALLOWED:
            raise SafetyError(f"shell command '{cmd}' is not allowed")
        rest = tokens[1:]
        if cmd == "am":
            if not rest or rest[0] not in AM_ALLOWED:
                raise SafetyError(f"'am {rest[0] if rest else ''}' is not allowed")
            if not self._mentions_package(rest[1:]):
                raise SafetyError(f"am command does not target the package under test ({self.package})")
        elif cmd == "pm":
            if not rest or rest[0] not in PM_ALLOWED:
                raise SafetyError("only 'pm path' and 'pm list' are allowed")
        elif cmd == "dumpsys":
            if not rest or rest[0] not in DUMPSYS_ALLOWED:
                raise SafetyError("dumpsys target is not allowed")
        elif cmd == "content":
            if not rest or rest[0] not in ("query", "read"):
                raise SafetyError("only read-only 'content query' and 'content read' are allowed")
            uri = self._arg_after(rest, "--uri")
            if not uri or not uri.startswith("content://"):
                raise SafetyError("content command needs a content:// --uri")
            authority = uri[len("content://"):].split("/", 1)[0].split("?", 1)[0]
            if authority not in self.authorities:
                raise SafetyError(f"authority '{authority}' does not belong to the package under test")
        elif cmd == "getprop":
            if len(rest) != 1 or not re.match(r"^[a-z0-9_.]+$", rest[0]):
                raise SafetyError("getprop takes exactly one property name")

    def _mentions_package(self, args: Iterable[str]) -> bool:
        args = list(args)
        comp = self._arg_after(args, "-n") or self._arg_after(args, "--component")
        if comp:
            return comp.split("/", 1)[0] == self.package
        return bool(args) and args[-1] == self.package

    @staticmethod
    def _arg_after(args: list[str], flag: str) -> Optional[str]:
        for i, a in enumerate(args[:-1]):
            if a == flag:
                return args[i + 1]
        return None

    def record(self, line: str) -> None:
        self.audit.append(line)
