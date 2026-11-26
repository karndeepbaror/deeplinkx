from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional

from ..errors import DynamicError, SafetyError
from .safety import SafetyPolicy


@dataclass
class AdbResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    raw: bytes = b""
    duration_ms: int = 0
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def text(self) -> str:
        return (self.stdout + ("\n" + self.stderr if self.stderr else "")).strip()


@dataclass
class Device:
    serial: str
    state: str
    info: dict[str, str]

    @property
    def is_emulator_serial(self) -> bool:
        return self.serial.startswith("emulator-")


def find_adb(explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    env = os.environ.get("DEEPLINKX_ADB")
    if env:
        return env
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        base = os.environ.get(var)
        if base:
            cand = os.path.join(base, "platform-tools", "adb")
            if os.path.isfile(cand):
                return cand
    found = shutil.which("adb")
    if not found:
        raise DynamicError("adb was not found. Install Android platform-tools or set DEEPLINKX_ADB / ANDROID_HOME.")
    return found


class Adb:
    """Thin wrapper over the adb binary. Never uses a local shell and checks every command with the safety policy."""

    def __init__(self, adb_path: Optional[str] = None, serial: Optional[str] = None, policy: Optional[SafetyPolicy] = None,
                 timeout: int = 20):
        self.adb = find_adb(adb_path)
        self.serial = serial
        self.policy = policy or SafetyPolicy()
        self.timeout = timeout
        self.policy.check_serial(serial)
        self.transcript: list[dict] = []

    # ---- low level
    def run(self, args: list[str], timeout: Optional[int] = None, binary: bool = False, check_policy: bool = True,
            stdin: Optional[bytes] = None) -> AdbResult:
        import time

        if check_policy:
            self.policy.check_adb(args)
        argv = [self.adb] + (["-s", self.serial] if self.serial and args[0] not in ("devices", "start-server",
                                                                                      "version") else []) + args
        t0 = time.monotonic()
        try:
            cp = subprocess.run(argv, capture_output=True, timeout=timeout or self.timeout, input=stdin, check=False)
            res = AdbResult(args, cp.returncode, "" if binary else cp.stdout.decode("utf-8", "replace"),
                            cp.stderr.decode("utf-8", "replace"), cp.stdout if binary else b"")
        except subprocess.TimeoutExpired as exc:
            res = AdbResult(args, 124, (exc.stdout or b"").decode("utf-8", "replace"), "timeout", timed_out=True)
        except FileNotFoundError as exc:
            raise DynamicError(f"cannot execute adb: {exc}") from exc
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        self.transcript.append({"cmd": " ".join(shlex.quote(a) for a in args), "rc": res.returncode,
                                "ms": res.duration_ms})
        self.policy.record("adb " + " ".join(shlex.quote(a) for a in args))
        return res

    def shell(self, tokens: list[str], timeout: Optional[int] = None) -> AdbResult:
        """tokens are quoted individually so the device shell cannot split or expand them."""
        return self._shell(tokens, timeout)

    def _shell(self, tokens: list[str], timeout: Optional[int]) -> AdbResult:
        self.policy.check_shell(tokens)
        return self.run(["shell", shlex.join(tokens)], timeout, check_policy=False)

    # ---- devices
    def devices(self) -> list[Device]:
        res = self.run(["devices", "-l"], check_policy=True)
        out = []
        for line in res.stdout.splitlines()[1:]:
            line = line.strip()
            if not line or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            info = dict(p.split(":", 1) for p in parts[2:] if ":" in p)
            out.append(Device(parts[0], parts[1], info))
        return out

    def pick_device(self) -> Device:
        devs = [d for d in self.devices() if d.state == "device"]
        if self.serial:
            for d in devs:
                if d.serial == self.serial:
                    return d
            raise DynamicError(f"device {self.serial} is not connected (or not authorised)")
        emus = [d for d in devs if d.is_emulator_serial]
        if len(emus) >= 1:
            self.serial = emus[0].serial
            return emus[0]
        if devs and self.policy.allow_physical:
            self.serial = devs[0].serial
            return devs[0]
        if devs:
            raise SafetyError("only physical devices are connected; start an emulator or pass --allow-physical")
        raise DynamicError("no device or emulator is connected (adb devices is empty)")

    def prop(self, name: str) -> str:
        return self._shell(["getprop", name], 10).stdout.strip()

    def is_emulator(self) -> bool:
        if self.serial and self.serial.startswith("emulator-"):
            return True
        return self.prop("ro.kernel.qemu") == "1" or self.prop("ro.boot.qemu") == "1" or \
            "emulator" in self.prop("ro.product.model").lower() or "sdk" in self.prop("ro.product.model").lower()

    def wait_boot(self, timeout: int = 180) -> bool:
        import time

        end = time.monotonic() + timeout
        self.run(["wait-for-device"], timeout=timeout)
        while time.monotonic() < end:
            if self.prop("sys.boot_completed") == "1":
                return True
            time.sleep(1.5)
        return False

    # ---- package + logs
    def package_installed(self, package: str) -> bool:
        return "package:" in self._shell(["pm", "path", package], 15).stdout

    def install(self, apk_path: str, replace: bool = True) -> AdbResult:
        args = ["install"] + (["-r", "-t"] if replace else []) + [apk_path]
        return self.run(args, timeout=240)

    def clear_logcat(self) -> None:
        self.run(["logcat", "-c"], timeout=10)

    def dump_logcat(self, limit: int = 60000) -> str:
        res = self.run(["logcat", "-d", "-v", "threadtime"], timeout=30)
        text = res.stdout
        return text[-limit:] if len(text) > limit else text

    def force_stop(self, package: str) -> None:
        self._shell(["am", "force-stop", package], 10)

    def focused_window(self) -> str:
        out = self._shell(["dumpsys", "window"], 15).stdout
        m = re.search(r"mCurrentFocus=Window\{[^ ]+ [^ ]+ ([^}]+)\}", out) or re.search(
            r"mFocusedApp=.*? ([\w.]+/[\w.$]+)", out)
        return m.group(1).strip() if m else ""

    def screenshot(self) -> bytes:
        res = self.run(["exec-out", "screencap", "-p"], timeout=20, binary=True)
        return res.raw if res.ok and res.raw.startswith(b"\x89PNG") else b""
