"""Example DEEPLINK X plugin: adds a rule, a dynamic test-case generator and a report section.

Copy it to ~/.deeplinkx/plugins/ (or use --plugins <dir>) to activate it. Plugins are ordinary Python and run with
your privileges, only load code you trust.
"""
from deeplinkx.analysis.inventory import concrete_uri


def register(api):
    @api.rule("PLG-001", "Deep link exposes an administrative route", "medium", "Plugin",
              "A deep link path contains 'admin' or 'debug'. Administrative routes should not be reachable from links.",
              "Remove the route from release builds or require authentication before handling it.",
              confidence="tentative", tags=("plugin",))
    def admin_routes(ctx, meta):
        for link in ctx.deep_links:
            if link.path and any(w in link.path.lower() for w in ("admin", "debug")):
                comp = ctx.manifest.find(link.component)
                yield ctx.hit(meta, comp, key=f"route:{link.path}")

    def extra_cases(link, ctx):
        # one extra, non-destructive case per link: the same URI with a trailing canary segment
        return [{"name": "plugin-trailing-canary", "category": "plugin",
                 "uri": concrete_uri(link, path_suffix="/dlx_plugin_canary"),
                 "description": "Plugin: trailing path segment"}]

    api.add_testcase_generator(extra_cases)

    def section(report):
        schemes = report["link_summary"]["schemes"]
        return {"title": "Schemes in use", "items": [f"{name}: {count}" for name, count in schemes.items()]}

    api.add_report_section(section)
