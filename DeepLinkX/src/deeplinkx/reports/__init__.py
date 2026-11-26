from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ..errors import DeeplinkXError
from .html_report import render_html
from .json_report import render_json, render_sarif
from .pdf_report import render_pdf

FORMATS = {"html": "html", "json": "json", "pdf": "pdf", "sarif": "sarif"}


def render(report: dict, fmt: str) -> bytes:
    fmt = fmt.lower()
    if fmt == "html":
        return render_html(report).encode("utf-8")
    if fmt == "json":
        return render_json(report).encode("utf-8")
    if fmt == "sarif":
        return render_sarif(report).encode("utf-8")
    if fmt == "pdf":
        return render_pdf(report)
    raise DeeplinkXError(f"unknown report format: {fmt} (choose from {', '.join(FORMATS)})")


def write_reports(report: dict, out_dir: str | Path, formats: Iterable[str], stem: str | None = None) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    pkg = report["apk"]["package"]
    stem = stem or f"deeplinkx-{pkg}-{report['meta']['created'].replace(':', '').replace('-', '')}"
    written = []
    for fmt in formats:
        ext = FORMATS.get(fmt.lower())
        if ext is None:
            raise DeeplinkXError(f"unknown report format: {fmt}")
        path = out / f"{stem}.{ext}"
        path.write_bytes(render(report, fmt))
        written.append(path)
    return written


__all__ = ["render", "write_reports", "render_html", "render_json", "render_pdf", "render_sarif", "FORMATS"]
