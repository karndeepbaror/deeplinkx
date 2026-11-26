from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional

from ..errors import DynamicError


def find_emulator() -> str:
    env = os.environ.get("DEEPLINKX_EMULATOR")
    if env:
        return env
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        base = os.environ.get(var)
        if base:
            cand = os.path.join(base, "emulator", "emulator")
            if os.path.isfile(cand):
                return cand
    found = shutil.which("emulator")
    if not found:
        raise DynamicError("the Android emulator binary was not found. Install the SDK emulator or set "
                           "DEEPLINKX_EMULATOR / ANDROID_HOME.")
    return found


def list_avds(emulator: Optional[str] = None) -> list[str]:
    cp = subprocess.run([emulator or find_emulator(), "-list-avds"], capture_output=True, text=True, timeout=30)
    return [l.strip() for l in cp.stdout.splitlines() if l.strip() and not l.startswith(("INFO", "WARNING"))]


def start_emulator(avd: str, port: int = 5554, headless: bool = True, emulator: Optional[str] = None,
                   extra: Optional[list[str]] = None) -> subprocess.Popen:
    """Boots an AVD with a read-only snapshot so the test run never changes the saved image."""
    argv = [emulator or find_emulator(), "-avd", avd, "-port", str(port), "-no-snapshot-save", "-read-only",
            "-no-boot-anim", "-no-audio"]
    if headless:
        argv += ["-no-window", "-gpu", "swiftshader_indirect"]
    argv += extra or []
    return subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop_emulator(adb, proc: Optional[subprocess.Popen] = None) -> None:
    try:
        adb.run(["emu", "kill"], timeout=15)
    except Exception:
        pass
    if proc is not None:
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
