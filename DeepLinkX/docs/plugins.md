# Plugins

A plugin is a Python file exposing `register(api)`. It runs with your privileges — load only code you trust.

```python
def register(api):
    @api.rule("PLG-001", "Title", "medium", "Plugin", "Description", "Remediation", confidence="tentative")
    def check(ctx, meta):
        for link in ctx.deep_links:
            yield ctx.hit(meta, ctx.manifest.find(link.component), key=f"route:{link.path}")

    api.add_testcase_generator(lambda link, ctx: [{"name": "x", "category": "plugin", "uri": "..."}])
    api.add_report_section(lambda report: {"title": "My section", "items": ["a", "b"]})
```

See `plugins/example_plugin.py`. Place files in `~/.deeplinkx/plugins/` or pass `--plugins <dir>`. Errors inside plugins are collected in
`meta.rule_errors` and never abort the scan. `deeplinkx plugins list` shows what loaded.
