from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .context import build_context

TEMPLATES = Path(__file__).parent / "templates"


def render_html(report: dict) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html", "j2"]),
                      trim_blocks=True, lstrip_blocks=True)
    return env.get_template("report.html.j2").render(**build_context(report))
