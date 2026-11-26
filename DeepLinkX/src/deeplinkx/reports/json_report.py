from __future__ import annotations

import json

SCHEMA_VERSION = "1.0"


def render_json(report: dict, indent: int = 2) -> str:
    doc = {"schema_version": SCHEMA_VERSION, **report}
    return json.dumps(doc, indent=indent, ensure_ascii=False, default=str) + "\n"


_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


def render_sarif(report: dict) -> str:
    """SARIF 2.1.0 so findings can be uploaded to code scanning dashboards in CI."""
    rules = {}
    results = []
    for f in report["findings"]:
        rules.setdefault(f["rule_id"], {
            "id": f["rule_id"], "name": f["title"], "shortDescription": {"text": f["title"]},
            "fullDescription": {"text": f["description"].split("\n")[0]},
            "help": {"text": f["remediation"]},
            "properties": {"category": f["category"], "tags": f["tags"]},
        })
        results.append({
            "ruleId": f["rule_id"], "level": _SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f"{f['title']}: {f['description'].splitlines()[0]}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": report["apk"]["file_name"]}},
                           "logicalLocations": [{"name": f.get("component") or report["apk"]["package"],
                                                 "kind": f.get("component_kind") or "package"}]}],
            "partialFingerprints": {"deeplinkx/v1": f["fingerprint"]},
            "properties": {"severity": f["severity"], "confidence": f["confidence"], "score": f["score"],
                           "status": f["status"]},
        })
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": report["meta"]["tool"], "version": report["meta"]["version"],
                            "informationUri": "https://github.com/karndeepbaror", "rules": list(rules.values())}},
        "results": results}]}
    return json.dumps(doc, indent=2) + "\n"
