# REST API (`/api/v1`)

Set `DEEPLINKX_API_TOKEN` (or `serve --token`) to require `Authorization: Bearer <token>`; `?token=` is accepted for EventSource and download links.
`/health` is always public. Binding to a non-local address without a token prints a warning.

| method & path | purpose |
|---|---|
| `GET /health`, `/info`, `/profiles`, `/rules` | metadata |
| `POST /scans?profile=standard&filename=a.apk&assetlinks=1` | raw APK in the request body (`application/octet-stream`) → `202` + job |
| `GET /jobs/{id}` · `GET /jobs/{id}/events` | job state · Server-Sent Events (`progress`, `end`) |
| `GET /scans?package=&limit=` · `GET /scans/{id}` · `DELETE /scans/{id}` | history |
| `GET /scans/{id}/report/{html\|json\|pdf\|sarif}?download=1` | reports |
| `GET /scans/{id}/graph` · `/scans/{a}/diff/{b}` · `/packages/{pkg}/trend` | graph, diff, risk trend |
| `POST /findings/status` `{package, finding, status, note}` | status tracking |

Limits: `DEEPLINKX_MAX_UPLOAD_MB` (default 300). Errors are `{"error": "..."}` with 400/401/404/413.

```python
from deeplinkx.api.client import Client
c = Client("http://127.0.0.1:8787", token="…")
report = c.scan("app.apk", profile="ci")
open("r.pdf", "wb").write(c.report(report["meta"]["scan_id"], "pdf"))
```

Dynamic runs are CLI-only by design: they need an authorised device and explicit confirmation.
