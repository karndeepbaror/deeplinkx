"""URI and component test-case generation.

All inputs are deliberately non-destructive: they carry a canary marker (`dlx_canary`, `canary.invalid`) so that
behaviour can be observed in logs without touching real data or real third party hosts (`.invalid` never resolves).
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional
from urllib.parse import quote

from ..analysis.analyzer import AnalysisResult
from ..analysis.inventory import concrete_uri
from ..config import DynamicSettings
from ..models import DeepLink

CANARY_HOST = "canary.invalid"
CANARY_URL = f"https://{CANARY_HOST}/dlx"
DEFAULT_PARAMS = ["url", "redirect", "next"]
CATEGORIES = ["baseline", "canary", "redirect", "host-confusion", "scheme-injection", "traversal", "long-input",
              "special-chars", "empty", "component", "provider", "plugin"]

__all__ = ["TestCase", "generate_cases", "CANARY_URL", "CANARY_HOST", "concrete_uri"]


@dataclass
class TestCase:
    __test__ = False  # not a pytest class

    id: str
    name: str
    category: str
    kind: str  # deeplink | component | provider
    component: str
    description: str
    argv: list[str]
    uri: Optional[str] = None
    link: Optional[str] = None
    expect: str = "launch"  # launch | denied | any
    tags: list[str] = field(default_factory=list)

    @property
    def command(self) -> str:
        return "adb shell " + shlex.join(self.argv)

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "category": self.category, "kind": self.kind,
                "component": self.component, "description": self.description, "command": self.command,
                "uri": self.uri, "link": self.link, "expect": self.expect, "tags": self.tags}


def _q(v: str) -> str:
    return quote(v, safe="")


def _am_view(package: str, component: str, uri: str) -> list[str]:
    return ["am", "start", "-W", "-n", f"{package}/{component}", "-a", "android.intent.action.VIEW",
            "-c", "android.intent.category.BROWSABLE", "-d", uri]


def _link_cases(package: str, link: DeepLink, params: list[str], ctx_gen) -> list[tuple[str, str, str, str]]:
    """(category, name, description, uri) tuples for one deep link."""
    base = concrete_uri(link)
    out: list[tuple[str, str, str, str]] = [("baseline", "baseline", "Plain URI that matches the filter", base)]
    out.append(("canary", "query-canary", "Adds a canary query parameter", concrete_uri(link, query="dlx=dlx_canary")))
    for p in params[:4]:
        out.append(("redirect", f"param-{p}-canary-url", f"Parameter '{p}' set to an external canary URL",
                    concrete_uri(link, query=f"{p}={_q(CANARY_URL)}")))
    p0 = params[0]
    out.append(("host-confusion", "host-suffix-trick", "Allow-listed host used as sub-domain of the canary host",
                concrete_uri(link, query=f"{p0}={_q('https://example.com.' + CANARY_HOST + '/')}")))
    out.append(("host-confusion", "host-in-query", "Allow-listed host only appears in the query string",
                concrete_uri(link, query=f"{p0}={_q('https://' + CANARY_HOST + '/?h=example.com')}")))
    out.append(("host-confusion", "userinfo-trick", "Allow-listed host used as user-info",
                concrete_uri(link, query=f"{p0}={_q('https://example.com@' + CANARY_HOST + '/')}")))
    out.append(("scheme-injection", "javascript-scheme", "javascript: URL in a URL-like parameter",
                concrete_uri(link, query=f"{p0}={_q('javascript:void(0)//dlx_canary')}")))
    out.append(("scheme-injection", "data-scheme", "data: URL in a URL-like parameter",
                concrete_uri(link, query=f"{p0}={_q('data:text/plain,dlx_canary')}")))
    out.append(("scheme-injection", "file-scheme", "file: URL pointing at /dev/null",
                concrete_uri(link, query=f"{p0}={_q('file:///dev/null')}")))
    out.append(("traversal", "path-traversal", "Encoded ../ segments in the path",
                concrete_uri(link, path_suffix="/..%2f..%2fdlx_canary")))
    out.append(("long-input", "long-parameter", "2000 character parameter value",
                concrete_uri(link, query="dlx=" + "A" * 2000)))
    out.append(("special-chars", "special-characters", "Quotes, null byte and unicode in a parameter",
                concrete_uri(link, query="dlx=" + _q("'\"<>%00‮☃dlx_canary"))))
    out.append(("empty", "empty-parameters", "Known parameters present but empty",
                concrete_uri(link, query="&".join(f"{p}=" for p in params[:3]))))
    return out


def generate_cases(analysis: AnalysisResult, settings: Optional[DynamicSettings] = None,
                   generators: Iterable[Callable] = (), ctx=None) -> list[TestCase]:
    settings = settings or DynamicSettings()
    pkg = analysis.manifest.package
    cases: list[TestCase] = []
    wanted = set(settings.categories)

    def keep(cat: str) -> bool:
        return not wanted or cat in wanted

    seen_uris: set[tuple[str, str]] = set()
    by_comp: dict[str, list[DeepLink]] = {}
    for l in analysis.deep_links:
        if l.exported and l.browsable:
            by_comp.setdefault(l.component, []).append(l)

    for comp_name, links in sorted(by_comp.items()):
        cc = analysis.code.for_component(comp_name)
        params = list(dict.fromkeys((cc.param_names if cc else []) + DEFAULT_PARAMS))
        for link in links:
            raw = _link_cases(pkg, link, params, None)
            for gen in generators:
                try:
                    for extra in gen(link, ctx) or []:
                        raw.append((extra.get("category", "plugin"), extra.get("name", "plugin-case"),
                                    extra.get("description", ""), extra["uri"]))
                except Exception:
                    continue
            count = 0
            for cat, name, desc, uri in raw:
                if not keep(cat) or (comp_name, uri) in seen_uris or count >= settings.max_cases_per_link:
                    continue
                seen_uris.add((comp_name, uri))
                count += 1
                cases.append(TestCase("", f"{name}", cat, "deeplink", comp_name, desc,
                                      _am_view(pkg, comp_name, uri), uri=uri, link=link.uri,
                                      tags=[link.scheme or "", "app-link" if link.is_app_link else "link"]))

    if settings.include_component_launch and keep("component"):
        for ep in analysis.entry_points:
            c = ep.component
            expect = "denied" if ep.guard == "strong" else "launch"
            if c.kind in ("activity", "activity-alias"):
                cases.append(TestCase("", "explicit-launch", "component", "component", c.name,
                                      "Explicit intent without extras", ["am", "start", "-W", "-n", f"{pkg}/{c.name}"],
                                      expect=expect))
            elif c.kind == "service":
                cases.append(TestCase("", "explicit-start", "component", "component", c.name,
                                      "Explicit service start without extras",
                                      ["am", "startservice", "-n", f"{pkg}/{c.name}"], expect=expect))
            elif c.kind == "receiver" and settings.include_receivers:
                cases.append(TestCase("", "explicit-broadcast", "component", "component", c.name,
                                      "Explicit broadcast without extras",
                                      ["am", "broadcast", "-n", f"{pkg}/{c.name}"], expect=expect))
    if settings.include_providers and (keep("provider") or keep("component")):
        for ep in analysis.entry_points:
            c = ep.component
            if c.kind != "provider" or not c.authorities:
                continue
            auth = c.authorities[0]
            expect = "denied" if ep.guard == "strong" else "any"
            cases.append(TestCase("", "provider-query", "provider", "provider", c.name,
                                  "Read-only query on the provider root", ["content", "query", "--uri", f"content://{auth}/"],
                                  expect=expect))
            cases.append(TestCase("", "provider-sql-quote", "provider", "provider", c.name,
                                  "Selection with a single quote to observe SQL errors",
                                  ["content", "query", "--uri", f"content://{auth}/", "--where", "dlx_canary'"],
                                  expect=expect))
            cases.append(TestCase("", "provider-traversal", "provider", "provider", c.name,
                                  "Encoded ../ segments when reading a file URI",
                                  ["content", "read", "--uri", f"content://{auth}/..%2f..%2fdlx_canary"],
                                  expect=expect))
    cases.sort(key=lambda t: (t.component, CATEGORIES.index(t.category) if t.category in CATEGORIES else 99, t.name))
    for i, t in enumerate(cases, start=1):
        t.id = f"T{i:03d}"
    return cases


def authorities(analysis: AnalysisResult) -> set[str]:
    return {a for c in analysis.manifest.components if c.kind == "provider" for a in c.authorities}
