# Dynamic testing safety

The dynamic engine sends deep links and intents to an app running on an Android device. Use it **only on applications you own or are
explicitly authorised to test, in an isolated environment.** DEEPLINK X enforces what it can:

* `--authorized` is mandatory; without it the command refuses (exit code 3).
* Emulators only. A physical device additionally needs `--allow-physical`.
* Only an allow-list of adb sub-commands and shell programs (`am start/startservice/broadcast/force-stop`, `pm path/list`, `content query/read`, `dumpsys window/activity/package`, `getprop`, `logcat`, `screencap`, `install`). No arbitrary shell: pipes, redirects and chaining are rejected, arguments are shell-quoted, and `uninstall` is limited to the package under test and off by default.
* Test inputs are inert **canary** values (`dlx_canary_…`) and well-known benign shapes (quotes, traversal-looking strings, loopback URLs). There are no exploit payloads.
* Every run writes evidence: `run.json`, logcat, screenshots, activity/window dumps, `transcript.log` of every adb command, and `repro.sh`.

The static analyser needs no device and never executes the APK.
