from __future__ import annotations

from itertools import product

from ..models import DataSpec, DeepLink, Manifest


def _combine(data: list[DataSpec]):
    schemes = sorted({d.scheme for d in data if d.scheme})
    hosts = []
    seen = set()
    for d in data:
        if d.host or d.port:
            k = (d.host, d.port)
            if k not in seen:
                seen.add(k)
                hosts.append(k)
    paths = []
    seen_p = set()
    for d in data:
        kind, val = d.path_kind()
        if kind:
            if (kind, val) not in seen_p:
                seen_p.add((kind, val))
                paths.append((kind, val))
    mimes = sorted({d.mime_type for d in data if d.mime_type})
    return schemes, hosts or [(None, None)], paths or [(None, None)], mimes or [None]


def build_inventory(manifest: Manifest) -> list[DeepLink]:
    """One DeepLink per scheme x host x path combination of each intent filter that has a data scheme."""
    links: list[DeepLink] = []
    for comp in manifest.components:
        if not comp.enabled:
            continue
        for fi, flt in enumerate(comp.filters):
            schemes, hosts, paths, mimes = _combine(flt.data)
            if not schemes:
                continue
            for scheme, (host, port), (pk, pv), mime in product(schemes, hosts, paths, mimes):
                links.append(DeepLink(
                    component=comp.name, kind=comp.kind, scheme=scheme, host=host, port=port,
                    path_kind=pk, path=pv, mime_type=mime, browsable=flt.browsable,
                    auto_verify=flt.auto_verify, exported=comp.effective_exported,
                    permission=comp.permission, filter_index=fi,
                    actions=list(flt.actions), categories=list(flt.categories),
                ))
    return links


def summarize_inventory(links: list[DeepLink]) -> dict:
    schemes: dict[str, int] = {}
    for l in links:
        schemes[l.scheme or "*"] = schemes.get(l.scheme or "*", 0) + 1
    return {
        "total": len(links),
        "web": sum(1 for l in links if l.is_web),
        "custom_scheme": sum(1 for l in links if not l.is_web),
        "app_links": sum(1 for l in links if l.is_app_link),
        "browsable": sum(1 for l in links if l.browsable),
        "schemes": dict(sorted(schemes.items())),
        "components": len({l.component for l in links}),
    }


def _fill_pattern(pattern: str) -> str:
    """Turn an Android pathPattern (simple glob) into a path that matches it."""
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            out.append(pattern[i + 1])
            i += 2
            continue
        if ch == "." and i + 1 < len(pattern) and pattern[i + 1] == "*":
            out.append("x")
            i += 2
            continue
        if ch == "*":
            out.append("x")
        elif ch == ".":
            out.append("x")
        else:
            out.append(ch)
        i += 1
    path = "".join(out)
    return path if path.startswith("/") else "/" + path


def concrete_uri(link: DeepLink, query: str | None = None, path_suffix: str = "") -> str:
    """A concrete URI that the intent filter of `link` accepts (used for tests and repro commands)."""
    scheme = link.scheme or "https"
    host = link.host or ""
    if host.startswith("*."):
        host = "www." + host[2:]
    elif host == "*":
        host = "example.com"
    if not host and (link.is_web):
        host = "example.com"
    if not host:
        host = "dlx"
    if link.port:
        host = f"{host}:{link.port}"
    kind, path = link.path_kind, link.path or ""
    if kind == "exact":
        p = path
    elif kind == "prefix":
        p = path + ("index" if path.endswith("/") else "")
        if not p.startswith("/"):
            p = "/" + p
    elif kind in ("pattern", "advanced"):
        p = _fill_pattern(path)
    elif kind == "suffix":
        p = "/x" + path
    else:
        p = ""
    p += path_suffix
    uri = f"{scheme}://{host}{p}"
    if query:
        uri += ("&" if "?" in uri else "?") + query
    return uri
