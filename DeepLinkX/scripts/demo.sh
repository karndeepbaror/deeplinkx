#!/usr/bin/env bash
# Build the bundled vulnerable demo APK (synthetic, test-only) and scan it.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=src:tests
python - <<'PY'
from fixtures.sample_apps import build_vulnerable_apk
print(build_vulnerable_apk("demo/shop-demo.apk"))
PY
python -m deeplinkx scan demo/shop-demo.apk -o demo/reports -f html,json,pdf,sarif --no-history "$@"
