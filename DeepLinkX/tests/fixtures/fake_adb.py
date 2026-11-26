#!/usr/bin/env python3
"""A tiny stand-in for adb used by the dynamic engine tests. State lives in $FAKE_ADB_DIR."""
import os
import shlex
import sys
import time
from pathlib import Path

STATE = Path(os.environ["FAKE_ADB_DIR"])
LOG = STATE / "logcat.txt"
PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
       b"\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe\xa7\x9a\xa1\x1f\x00\x00\x00\x00IEND\xaeB`\x82")
PKG = "com.shop.demo"


def log(line):
    with open(LOG, "a") as fh:
        fh.write(line + "\n")


def out(text=""):
    sys.stdout.write(text)
    if text and not text.endswith("\n"):
        sys.stdout.write("\n")


args = sys.argv[1:]
with open(STATE / "calls.txt", "a") as fh:
    fh.write(shlex.join(args) + "\n")
if args[:1] == ["-s"]:
    args = args[2:]
cmd = args[0] if args else ""

if cmd == "devices":
    out("List of devices attached")
    for line in os.environ.get("FAKE_ADB_DEVICES", "emulator-5554\tdevice product:sdk model:sdk_gphone device:emu").split(";"):
        out(line.replace("\\t", "\t"))
elif cmd in ("wait-for-device", "start-server"):
    pass
elif cmd == "install":
    out("Performing Streamed Install\nSuccess")
elif cmd == "logcat":
    if "-c" in args:
        LOG.write_text("")
    else:
        out(LOG.read_text() if LOG.exists() else "")
elif cmd == "exec-out":
    sys.stdout.buffer.write(PNG)
elif cmd == "emu":
    out("OK")
elif cmd == "shell":
    toks = shlex.split(" ".join(args[1:]))
    head = toks[0]
    if head == "getprop":
        emu = os.environ.get("FAKE_ADB_PHYSICAL") != "1"
        vals = {"ro.kernel.qemu": "1" if emu else "", "ro.boot.qemu": "1" if emu else "",
                "sys.boot_completed": "1", "ro.product.model": "sdk_gphone64" if emu else "Pixel 7"}
        out(vals.get(toks[1], ""))
    elif head == "pm":
        if toks[1] == "path":
            if os.environ.get("FAKE_ADB_NOT_INSTALLED") != "1" and toks[2] == PKG:
                out("package:/data/app/~~x/base.apk")
    elif head == "dumpsys":
        out(f"  mCurrentFocus=Window{{1a2b3c u0 {PKG}/{PKG}.DeepLinkActivity}}")
    elif head == "am":
        sub = toks[1]
        if sub == "force-stop":
            pass
        elif sub == "start":
            if os.environ.get("FAKE_ADB_HANG") == "1":
                time.sleep(30)
            comp = toks[toks.index("-n") + 1] if "-n" in toks else ""
            uri = toks[toks.index("-d") + 1] if "-d" in toks else ""
            if comp.endswith("AdminActivity"):
                out("Starting: Intent { cmp=%s }" % comp)
                sys.stderr.write("java.lang.SecurityException: Permission Denial: starting Intent { cmp=%s } "
                                 "requires com.shop.demo.ADMIN\n" % comp)
            else:
                if "AAAAAAAAAA" in uri:
                    log("E AndroidRuntime: FATAL EXCEPTION: main")
                    log("E AndroidRuntime: Process: com.shop.demo, PID: 4242")
                    log("E AndroidRuntime: java.lang.IllegalStateException: boom in com.shop.demo.DeepLinkActivity")
                if "canary.invalid" in uri and "javascript" not in uri and "data%3A" not in uri:
                    log("D WebView: com.shop.demo loadUrl https://canary.invalid/dlx")
                out("Starting: Intent { cmp=%s }\nStatus: ok\nLaunchState: COLD\nActivity: %s\nTotalTime: 150\n"
                    "WaitTime: 160\nComplete" % (comp, comp))
                log(f"I ActivityTaskManager: START u0 {comp}")
        elif sub == "startservice":
            out("Starting service: Intent { cmp=%s }" % toks[toks.index("-n") + 1])
        elif sub == "broadcast":
            out("Broadcast completed: result=0")
    elif head == "content":
        uri = toks[toks.index("--uri") + 1]
        if toks[1] == "query":
            if "--where" in toks and "'" in toks[toks.index("--where") + 1]:
                log("E DatabaseUtils: android.database.sqlite.SQLiteException: unrecognized token: \"'\" (code 1)")
                out("Error while accessing provider:com.shop.demo.data\n"
                    "android.database.sqlite.SQLiteException: unrecognized token")
            else:
                out("Row: 0 _id=1, name=alice\nRow: 1 _id=2, name=bob")
        elif toks[1] == "read":
            out("Row: 0 data=root:x:0:0" if "..%2f" in uri else "")
    else:
        sys.stderr.write("/system/bin/sh: %s: inaccessible or not found\n" % head)
        sys.exit(127)
else:
    sys.stderr.write("unknown command\n")
    sys.exit(1)
