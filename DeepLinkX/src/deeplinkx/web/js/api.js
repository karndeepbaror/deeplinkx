let token = null;
try { token = sessionStorage.getItem("dlx-token"); } catch {}
export const setToken = t => { token = t; try { sessionStorage.setItem("dlx-token", t); } catch {} };
export const getToken = () => token;
const BASE = "api/v1";
export class ApiError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

async function call(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (token) headers.Authorization = "Bearer " + token;
  const res = await fetch(BASE + path, { ...opts, headers });
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).error || msg; } catch {}
    throw new ApiError(res.status, msg);
  }
  return res;
}
const json = async (p, o) => (await call(p, o)).json();
export const api = {
  health: () => fetch(BASE + "/health").then(r => r.json()),
  info: () => json("/info"),
  rules: () => json("/rules"),
  scans: (pkg) => json("/scans?limit=200" + (pkg ? "&package=" + encodeURIComponent(pkg) : "")),
  scan: id => json("/scans/" + id),
  graph: id => json(`/scans/${id}/graph`),
  diff: (a, b) => json(`/scans/${a}/diff/${b}`),
  trend: pkg => json(`/packages/${encodeURIComponent(pkg)}/trend`),
  del: id => json("/scans/" + id, { method: "DELETE" }),
  status: (package_, finding, status) => json("/findings/status", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ package: package_, finding, status }) }),
  upload: (file, profile, assetlinks) => json(`/scans?profile=${encodeURIComponent(profile)}&filename=${encodeURIComponent(file.name)}${assetlinks ? "&assetlinks=1" : ""}`, { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: file }),
  job: id => json("/jobs/" + id),
  eventsUrl: id => `${BASE}/jobs/${id}/events` + (token ? "?token=" + encodeURIComponent(token) : ""),
  reportUrl: (id, fmt, dl) => `${BASE}/scans/${id}/report/${fmt}?${dl ? "download=1&" : ""}${token ? "token=" + encodeURIComponent(token) : ""}`,
};
