# Architecture

```
apk/        binary AXML, resources.arsc, DEX, ZIP + signing blocks     -> Apk, Manifest, Dex
analysis/   inventory, entry points, permissions, netsec, code graph, assetlinks -> AnalysisResult
rules/      builtin (55) + YAML + plugins -> Registry
findings/   run_rules -> dedupe -> filters -> finalize (ids, score) ; SQLite Store (history, statuses, diff)
scan.py     run_scan(): the whole static pipeline -> ScanReport.to_dict()  (single JSON-able report model)
dynamic/    safety policy, adb wrapper, emulator, test-case generator, observer, runner, evidence
reports/    Jinja2 HTML, reportlab PDF, JSON, SARIF — all render from the report dict
ui/         ANSI terminal: Console, widgets, banner, live scan display, views, interactive browser
cli/        click commands
api/        Starlette REST + SSE, job manager, graph builder, Python client
web/        dashboard (ES modules, canvas graph)
```

Design rules

* **One report dict.** CLI, API, history, every report format and the dashboard consume the same structure, so they cannot drift.
* **Findings are fingerprinted** (`sha1(rule | component | key)`), which makes de-duplication, diffing between scans and status tracking stable.
* **Rules never crash a scan.** Plugin or YAML failures are isolated and surfaced in `meta.rule_errors`.
* **Hostile input is assumed.** APK strings are escaped in HTML (Jinja autoescape), the dashboard builds DOM through text nodes only, assetlinks fetching refuses private/loopback hosts (SSRF), uploads are size-limited and type-checked.
* **Dynamic testing is gated** by `SafetyPolicy` — see [safety.md](safety.md).

## Risk score

Weighted by severity × confidence, saturating; capped at 94 unless a Critical finding exists so that "100" always means something.
The risk *level* is the highest active severity (None / Info / Low / Medium / High / Critical); the score is for trending and sorting.
