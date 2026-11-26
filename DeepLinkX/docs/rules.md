# Custom rules (YAML)

```yaml
rules:
  - id: ORG-001
    title: Payment screen is externally reachable
    severity: high              # critical | high | medium | low | info
    confidence: firm            # confirmed | firm | tentative (default firm)
    category: Policy
    description: ...
    impact: ...
    remediation: ...
    tags: [policy]
    when:
      kind: [activity]
      exported: true
      guard: none
      name_regex: "(?i)(payment|checkout)"
```

Every key under `when` must hold for a component (AND). Supported conditions:

| key | meaning |
|---|---|
| `kind` | component kind(s): activity, service, receiver, provider, activity-alias |
| `exported`, `guard`, `permission`, `name_regex` | exposure and protection |
| `has_deep_link`, `browsable`, `scheme`, `host_regex`, `path_regex` | deep link shape |
| `indicators`, `any_indicators` | code indicators reachable from the component (e.g. `sink_webview_load`, `input_uri`) |
| `uses_permission`, `debuggable` | app-level facts |

Unknown keys fail validation: `deeplinkx rules validate my-rules.yaml`. Load with `--rules <file|dir>` or place in `~/.deeplinkx/rules/`.
`deeplinkx rules list` shows built-in rule IDs; `rules show DLX-101` prints a rule in full. Disable or re-grade rules per profile
(`disabled_rules`, `severity_overrides`).
