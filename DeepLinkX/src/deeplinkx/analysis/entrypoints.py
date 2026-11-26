from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models import Component, Manifest
from .permissions import NONE, STRONG, guard_strength, strongest

DEBUG_NAME = re.compile(r"(debug|test|dev|internal|admin|staging|mock|sandbox|hidden|secret|backdoor)", re.I)


@dataclass
class EntryPoint:
    component: Component
    reasons: list[str] = field(default_factory=list)
    guard: str = NONE
    is_launcher: bool = False
    deep_link_count: int = 0
    unintended: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.component.name

    @property
    def kind(self) -> str:
        return self.component.kind

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "reasons": self.reasons,
            "guard": self.guard,
            "is_launcher": self.is_launcher,
            "deep_links": self.deep_link_count,
            "unintended": self.unintended,
            "permission": self.component.permission,
            "read_permission": self.component.read_permission,
            "write_permission": self.component.write_permission,
            "authorities": self.component.authorities,
            "actions": sorted({a for f in self.component.filters for a in f.actions}),
        }


def component_guard(c: Component, m: Manifest) -> str:
    if c.kind == "provider":
        r = guard_strength(c.read_permission or c.permission, m)
        w = guard_strength(c.write_permission or c.permission, m)
        base = min((r, w), key=lambda s: ["none", "weak", "medium", "strong"].index(s))
        for pp in c.path_permissions:
            # a per-path permission can only narrow exposure of the matching paths; keep the weakest default
            pass
        return base
    return guard_strength(c.permission, m)


def find_entry_points(manifest: Manifest, deep_links) -> list[EntryPoint]:
    counts: dict[str, int] = {}
    for l in deep_links:
        counts[l.component] = counts.get(l.component, 0) + 1
    out: list[EntryPoint] = []
    for c in manifest.components:
        if not c.enabled or not c.effective_exported:
            continue
        ep = EntryPoint(component=c, guard=component_guard(c, manifest), deep_link_count=counts.get(c.name, 0))
        ep.is_launcher = any(f.is_launcher for f in c.filters)
        if c.exported is True:
            ep.reasons.append("explicit android:exported=\"true\"")
        elif c.kind == "provider":
            ep.reasons.append("provider exported by default (targetSdk <= 16)")
        else:
            ep.reasons.append("implicitly exported through an intent filter")
        if c.filters:
            ep.reasons.append(f"{len(c.filters)} intent filter(s)")
        # ---- potentially unintended entry points
        if c.exported is True and not c.filters and not ep.is_launcher and ep.guard != STRONG:
            ep.unintended.append("exported without any intent filter (explicit-intent only target)")
        if c.exported is None and c.filters and (manifest.target_sdk or 0) < 31 and c.kind != "provider":
            ep.unintended.append("export is implicit; set android:exported explicitly")
        if DEBUG_NAME.search(c.short_name) and not ep.is_launcher:
            ep.unintended.append("component name suggests debug/test/internal functionality")
        if c.kind == "activity-alias" and c.target_activity:
            target = manifest.find(c.target_activity)
            if target is not None and not target.effective_exported:
                ep.unintended.append(f"alias exposes non-exported activity {target.short_name}")
        if c.kind == "provider" and c.grant_uri_permissions and not c.permission:
            ep.unintended.append("grantUriPermissions enabled on an exported provider")
        if c.kind in ("service", "receiver") and not c.filters and c.exported is True and ep.guard == NONE:
            ep.unintended.append(f"unprotected exported {c.kind} without filters")
        out.append(ep)
    return out


def exposure_summary(entry_points: list[EntryPoint], manifest: Manifest) -> dict:
    by_kind: dict[str, int] = {}
    unprotected = 0
    for ep in entry_points:
        by_kind[ep.kind] = by_kind.get(ep.kind, 0) + 1
        if ep.guard == NONE and not ep.is_launcher:
            unprotected += 1
    return {
        "components_total": len(manifest.components),
        "exported_total": len(entry_points),
        "by_kind": by_kind,
        "unprotected": unprotected,
        "unintended": sum(1 for e in entry_points if e.unintended),
        "strongest_guard": strongest(*(e.guard for e in entry_points)) if entry_points else NONE,
    }
