#!/usr/bin/env python3
"""Build a clean release archive: python scripts/build_zip.py [output.zip]"""
import re
import sys
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
version = re.search(r'__version__\s*=\s*"([^"]+)"', (root / "src/deeplinkx/version.py").read_text()).group(1)
out = Path(sys.argv[1]) if len(sys.argv) > 1 else root.parent / f"deeplinkx-{version}.zip"
SKIP_DIRS = {"__pycache__", ".pytest_cache", "deeplinkx-reports", "deeplinkx-evidence", "dist", "build", ".git", "demo"}
count = 0
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if p.is_dir() or SKIP_DIRS & set(rel.parts) or p.suffix == ".pyc" or ".egg-info" in str(rel):
            continue
        info = zipfile.ZipInfo.from_file(p, f"deeplinkx-{version}/{rel}")
        info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, p.read_bytes())
        count += 1
print(f"wrote {out} ({count} files, {out.stat().st_size // 1024} KB)")
