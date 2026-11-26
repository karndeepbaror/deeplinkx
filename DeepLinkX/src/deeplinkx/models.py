from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.title() if self is not Severity.INFO else "Info"

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        key = str(value).strip().upper()
        aliases = {"INFORMATIONAL": "INFO", "WARNING": "MEDIUM", "ERROR": "HIGH"}
        key = aliases.get(key, key)
        try:
            return cls[key]
        except KeyError:
            raise ValueError(f"unknown severity: {value!r}") from None


class Confidence(enum.IntEnum):
    TENTATIVE = 1
    FIRM = 2
    CERTAIN = 3

    @property
    def label(self) -> str:
        return self.name.title()

    @classmethod
    def parse(cls, value: Any) -> "Confidence":
        if isinstance(value, Confidence):
            return value
        if isinstance(value, int):
            return cls(value)
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            raise ValueError(f"unknown confidence: {value!r}") from None


class Status(str, enum.Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED = "accepted"
    FIXED = "fixed"

    @classmethod
    def parse(cls, value: Any) -> "Status":
        if isinstance(value, Status):
            return value
        key = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        try:
            return cls(key)
        except ValueError:
            raise ValueError(f"unknown status: {value!r}") from None


COMPONENT_KINDS = ("activity", "activity-alias", "service", "receiver", "provider")


@dataclass
class DataSpec:
    scheme: Optional[str] = None
    host: Optional[str] = None
    port: Optional[str] = None
    path: Optional[str] = None
    path_prefix: Optional[str] = None
    path_pattern: Optional[str] = None
    path_advanced_pattern: Optional[str] = None
    path_suffix: Optional[str] = None
    mime_type: Optional[str] = None

    def path_kind(self) -> tuple[Optional[str], Optional[str]]:
        if self.path is not None:
            return "exact", self.path
        if self.path_prefix is not None:
            return "prefix", self.path_prefix
        if self.path_pattern is not None:
            return "pattern", self.path_pattern
        if self.path_advanced_pattern is not None:
            return "advanced", self.path_advanced_pattern
        if self.path_suffix is not None:
            return "suffix", self.path_suffix
        return None, None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class IntentFilter:
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    data: list[DataSpec] = field(default_factory=list)
    auto_verify: bool = False
    priority: Optional[int] = None

    @property
    def browsable(self) -> bool:
        return "android.intent.category.BROWSABLE" in self.categories

    @property
    def is_launcher(self) -> bool:
        return (
            "android.intent.action.MAIN" in self.actions
            and "android.intent.category.LAUNCHER" in self.categories
        )

    @property
    def has_view(self) -> bool:
        return "android.intent.action.VIEW" in self.actions

    @property
    def schemes(self) -> list[str]:
        return sorted({d.scheme for d in self.data if d.scheme})

    def to_dict(self) -> dict:
        return {
            "actions": self.actions,
            "categories": self.categories,
            "data": [d.to_dict() for d in self.data],
            "auto_verify": self.auto_verify,
            "priority": self.priority,
        }


@dataclass
class Component:
    kind: str
    name: str
    exported: Optional[bool] = None
    enabled: bool = True
    permission: Optional[str] = None
    read_permission: Optional[str] = None
    write_permission: Optional[str] = None
    authorities: list[str] = field(default_factory=list)
    grant_uri_permissions: bool = False
    path_permissions: list[dict] = field(default_factory=list)
    filters: list[IntentFilter] = field(default_factory=list)
    target_activity: Optional[str] = None
    launch_mode: Optional[str] = None
    task_affinity: Optional[str] = None
    process: Optional[str] = None
    direct_boot_aware: bool = False
    meta_data: dict[str, str] = field(default_factory=dict)
    attrs: dict[str, Any] = field(default_factory=dict)
    effective_exported: bool = False

    @property
    def short_name(self) -> str:
        return self.name.rsplit(".", 1)[-1]

    @property
    def has_filters(self) -> bool:
        return bool(self.filters)

    @property
    def protected(self) -> bool:
        if self.kind == "provider":
            return bool(self.permission or (self.read_permission and self.write_permission))
        return bool(self.permission)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "name": self.name,
            "exported": self.exported,
            "effective_exported": self.effective_exported,
            "enabled": self.enabled,
            "permission": self.permission,
            "read_permission": self.read_permission,
            "write_permission": self.write_permission,
            "authorities": self.authorities,
            "grant_uri_permissions": self.grant_uri_permissions,
            "path_permissions": self.path_permissions,
            "filters": [f.to_dict() for f in self.filters],
            "target_activity": self.target_activity,
            "launch_mode": self.launch_mode,
            "task_affinity": self.task_affinity,
            "process": self.process,
            "direct_boot_aware": self.direct_boot_aware,
            "meta_data": self.meta_data,
        }


@dataclass
class DeepLink:
    component: str
    kind: str
    scheme: Optional[str]
    host: Optional[str]
    port: Optional[str]
    path_kind: Optional[str]
    path: Optional[str]
    mime_type: Optional[str]
    browsable: bool
    auto_verify: bool
    exported: bool
    permission: Optional[str]
    filter_index: int
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)

    @property
    def is_web(self) -> bool:
        return (self.scheme or "").lower() in ("http", "https")

    @property
    def is_app_link(self) -> bool:
        return self.is_web and self.auto_verify and self.browsable

    @property
    def uri(self) -> str:
        scheme = self.scheme or "*"
        host = self.host or ""
        if self.port:
            host = f"{host or '*'}:{self.port}"
        base = f"{scheme}://{host}"
        if self.path_kind == "exact":
            return base + (self.path or "")
        if self.path_kind == "prefix":
            return base + (self.path or "") + "*"
        if self.path_kind in ("pattern", "advanced"):
            return base + (self.path or "")
        if self.path_kind == "suffix":
            return base + "/*" + (self.path or "")
        return base

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["uri"] = self.uri
        d["is_app_link"] = self.is_app_link
        return d


@dataclass
class Manifest:
    package: str = ""
    version_code: Optional[int] = None
    version_name: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    compile_sdk: Optional[int] = None
    app_label: Optional[str] = None
    app_class: Optional[str] = None
    debuggable: bool = False
    allow_backup: Optional[bool] = None
    uses_cleartext: Optional[bool] = None
    test_only: bool = False
    network_security_config: Optional[str] = None
    shared_user_id: Optional[str] = None
    full_backup_content: Optional[str] = None
    data_extraction_rules: Optional[str] = None
    request_legacy_storage: bool = False
    uses_permissions: list[dict] = field(default_factory=list)
    declared_permissions: list[dict] = field(default_factory=list)
    uses_features: list[dict] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    app_attrs: dict[str, Any] = field(default_factory=dict)

    def by_kind(self, kind: str) -> list[Component]:
        return [c for c in self.components if c.kind == kind]

    @property
    def permission_names(self) -> list[str]:
        return [p["name"] for p in self.uses_permissions]

    def find(self, name: str) -> Optional[Component]:
        for c in self.components:
            if c.name == name:
                return c
        return None

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "version_code": self.version_code,
            "version_name": self.version_name,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "compile_sdk": self.compile_sdk,
            "app_label": self.app_label,
            "app_class": self.app_class,
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
            "uses_cleartext": self.uses_cleartext,
            "test_only": self.test_only,
            "network_security_config": self.network_security_config,
            "shared_user_id": self.shared_user_id,
            "uses_permissions": self.uses_permissions,
            "declared_permissions": self.declared_permissions,
            "uses_features": self.uses_features,
            "components": [c.to_dict() for c in self.components],
        }


@dataclass
class Evidence:
    kind: str
    title: str
    content: str

    def to_dict(self) -> dict:
        return {"kind": self.kind, "title": self.title, "content": self.content}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    description: str
    remediation: str
    component: Optional[str] = None
    component_kind: Optional[str] = None
    impact: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    reproduction: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    key: str = ""
    source: str = "static"
    status: Status = Status.OPEN
    occurrences: int = 1
    affected: list[str] = field(default_factory=list)
    score: float = 0.0
    id: str = ""

    @property
    def fingerprint(self) -> str:
        raw = "|".join([self.rule_id, self.component or "", self.key])
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name,
            "confidence": self.confidence.name,
            "category": self.category,
            "component": self.component,
            "component_kind": self.component_kind,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "evidence": [e.to_dict() for e in self.evidence],
            "references": self.references,
            "reproduction": self.reproduction,
            "tags": self.tags,
            "key": self.key,
            "source": self.source,
            "status": self.status.value,
            "occurrences": self.occurrences,
            "affected": self.affected,
            "score": round(self.score, 2),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(
            id=d.get("id", ""),
            rule_id=d["rule_id"],
            title=d["title"],
            severity=Severity.parse(d["severity"]),
            confidence=Confidence.parse(d["confidence"]),
            category=d.get("category", ""),
            component=d.get("component"),
            component_kind=d.get("component_kind"),
            description=d.get("description", ""),
            impact=d.get("impact", ""),
            remediation=d.get("remediation", ""),
            evidence=[Evidence(**e) for e in d.get("evidence", [])],
            references=list(d.get("references", [])),
            reproduction=list(d.get("reproduction", [])),
            tags=list(d.get("tags", [])),
            key=d.get("key", ""),
            source=d.get("source", "static"),
            status=Status.parse(d.get("status", "open")),
            occurrences=int(d.get("occurrences", 1)),
            affected=list(d.get("affected", [])),
            score=float(d.get("score", 0.0)),
        )
