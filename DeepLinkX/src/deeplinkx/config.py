from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from .errors import ProfileError
from .models import Confidence, Severity

PACKAGE_DIR = Path(__file__).resolve().parent
BUILTIN_PROFILES = PACKAGE_DIR / "profiles"
BUILTIN_RULES = PACKAGE_DIR / "rules"


def home_dir() -> Path:
    base = os.environ.get("DEEPLINKX_HOME")
    path = Path(base) if base else Path.home() / ".deeplinkx"
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass
class DynamicSettings:
    max_cases_per_link: int = 18
    settle_ms: int = 1500
    command_timeout: int = 20
    screenshots: bool = True
    categories: list[str] = field(default_factory=list)
    include_component_launch: bool = True
    include_providers: bool = True
    include_receivers: bool = False


@dataclass
class Profile:
    name: str = "standard"
    description: str = ""
    enabled_rules: Optional[list[str]] = None
    disabled_rules: list[str] = field(default_factory=list)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    min_severity: Severity = Severity.INFO
    min_confidence: Confidence = Confidence.TENTATIVE
    code_analysis: bool = True
    verify_assetlinks: bool = False
    assetlinks_timeout: float = 6.0
    rule_files: list[str] = field(default_factory=list)
    plugin_dirs: list[str] = field(default_factory=list)
    report_formats: list[str] = field(default_factory=lambda: ["html", "json"])
    fail_on: Optional[Severity] = None
    dynamic: DynamicSettings = field(default_factory=DynamicSettings)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "enabled_rules": self.enabled_rules,
            "disabled_rules": self.disabled_rules,
            "severity_overrides": {k: v.name for k, v in self.severity_overrides.items()},
            "min_severity": self.min_severity.name,
            "min_confidence": self.min_confidence.name,
            "code_analysis": self.code_analysis,
            "verify_assetlinks": self.verify_assetlinks,
            "report_formats": self.report_formats,
            "fail_on": self.fail_on.name if self.fail_on else None,
            "dynamic": self.dynamic.__dict__,
        }


def _profile_from_mapping(data: dict[str, Any], origin: str) -> Profile:
    if not isinstance(data, dict):
        raise ProfileError(f"{origin}: profile must be a mapping")
    known = {
        "name", "description", "enabled_rules", "disabled_rules", "severity_overrides",
        "min_severity", "min_confidence", "code_analysis", "verify_assetlinks",
        "assetlinks_timeout", "rule_files", "plugin_dirs", "report_formats", "fail_on", "dynamic",
    }
    unknown = set(data) - known
    if unknown:
        raise ProfileError(f"{origin}: unknown keys {sorted(unknown)}")
    p = Profile()
    try:
        p.name = str(data.get("name", p.name))
        p.description = str(data.get("description", ""))
        if data.get("enabled_rules") is not None:
            p.enabled_rules = [str(x) for x in data["enabled_rules"]]
        p.disabled_rules = [str(x) for x in data.get("disabled_rules", [])]
        p.severity_overrides = {
            str(k): Severity.parse(v) for k, v in (data.get("severity_overrides") or {}).items()
        }
        if "min_severity" in data:
            p.min_severity = Severity.parse(data["min_severity"])
        if "min_confidence" in data:
            p.min_confidence = Confidence.parse(data["min_confidence"])
        p.code_analysis = bool(data.get("code_analysis", p.code_analysis))
        p.verify_assetlinks = bool(data.get("verify_assetlinks", p.verify_assetlinks))
        p.assetlinks_timeout = float(data.get("assetlinks_timeout", p.assetlinks_timeout))
        p.rule_files = [str(x) for x in data.get("rule_files", [])]
        p.plugin_dirs = [str(x) for x in data.get("plugin_dirs", [])]
        if "report_formats" in data:
            p.report_formats = [str(x).lower() for x in data["report_formats"]]
        if data.get("fail_on"):
            p.fail_on = Severity.parse(data["fail_on"])
        dyn = data.get("dynamic") or {}
        bad = set(dyn) - set(DynamicSettings.__dataclass_fields__)
        if bad:
            raise ProfileError(f"{origin}: unknown dynamic keys {sorted(bad)}")
        p.dynamic = DynamicSettings(**dyn)
    except ValueError as exc:
        raise ProfileError(f"{origin}: {exc}") from exc
    return p


def list_profiles() -> list[str]:
    names = {p.stem for p in BUILTIN_PROFILES.glob("*.yaml")}
    user = home_dir() / "profiles"
    if user.is_dir():
        names |= {p.stem for p in user.glob("*.yaml")}
    return sorted(names)


def load_profile(ref: Optional[str] = None) -> Profile:
    ref = ref or "standard"
    candidates = [Path(ref)]
    if not ref.endswith((".yaml", ".yml")):
        candidates = [home_dir() / "profiles" / f"{ref}.yaml", BUILTIN_PROFILES / f"{ref}.yaml"]
    for path in candidates:
        if path.is_file():
            with open(path, "r", encoding="utf-8") as fh:
                try:
                    data = yaml.safe_load(fh) or {}
                except yaml.YAMLError as exc:
                    raise ProfileError(f"{path}: {exc}") from exc
            profile = _profile_from_mapping(data, str(path))
            if profile.name == "standard" and ref not in ("standard",) and "name" not in data:
                profile.name = Path(ref).stem
            return profile
    raise ProfileError(f"profile not found: {ref}")
