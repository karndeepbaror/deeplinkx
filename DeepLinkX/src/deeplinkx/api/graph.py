"""Attack-surface graph: app -> entry points -> deep links / permissions, with finding counts per node."""
from __future__ import annotations

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def build_graph(report: dict) -> dict:
    pkg = report["apk"]["package"]
    nodes: list[dict] = [{"id": "app", "type": "app", "label": pkg, "severity": None, "meta": {}}]
    edges: list[dict] = []
    by_comp: dict[str, list[dict]] = {}
    for f in report["findings"]:
        if f.get("component") and f.get("status") not in ("false_positive", "fixed", "accepted"):
            by_comp.setdefault(f["component"], []).append(f)

    def worst(items: list[dict]) -> str | None:
        sevs = {i["severity"] for i in items}
        return next((s for s in SEV_ORDER if s in sevs), None)

    for ep in report["entry_points"]:
        items = by_comp.get(ep["name"], [])
        nodes.append({"id": "c:" + ep["name"], "type": ep["kind"], "label": ep["name"].rsplit(".", 1)[-1],
                      "severity": worst(items), "meta": {"name": ep["name"], "guard": ep["guard"],
                                                         "findings": len(items), "reasons": ep["reasons"]}})
        edges.append({"from": "app", "to": "c:" + ep["name"], "kind": "exports", "guard": ep["guard"]})
    seen = set()
    for i, dl in enumerate(report["deep_links"]):
        nid = "d:" + dl["uri"]
        if nid not in seen:
            seen.add(nid)
            nodes.append({"id": nid, "type": "deeplink", "label": dl["uri"], "severity": None,
                          "meta": {"app_link": dl["is_app_link"], "browsable": dl["browsable"], "verified": dl["auto_verify"]}})
        edges.append({"from": nid, "to": "c:" + dl["component"], "kind": "routes", "guard": "none"})
    for perm in report["permissions"].get("dangerous", [])[:20]:
        name = perm if isinstance(perm, str) else perm.get("name", "")
        nodes.append({"id": "p:" + name, "type": "permission", "label": name.rsplit(".", 1)[-1], "severity": None,
                      "meta": {"name": name}})
        edges.append({"from": "app", "to": "p:" + name, "kind": "requests", "guard": "none"})
    ids = {n["id"] for n in nodes}
    edges = [e for e in edges if e["from"] in ids and e["to"] in ids]
    return {"nodes": nodes, "edges": edges}
