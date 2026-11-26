// Safe DOM construction: data is only ever inserted as text nodes, never as HTML.
export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}
export const sev = s => h("span", { class: "sev " + s }, s);
export const pill = (t, c = "") => h("span", { class: "pill " + c }, t);
export const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
export const SEV_COLOR = { CRITICAL: "var(--crit)", HIGH: "var(--high)", MEDIUM: "var(--med)", LOW: "var(--low)", INFO: "var(--info)" };
export function toast(msg, err = false) {
  const t = h("div", { class: "toast" + (err ? " err" : "") }, msg);
  document.getElementById("toasts").append(t);
  setTimeout(() => t.remove(), 4500);
}
export function countUp(el, to, ms = 800) {
  const t0 = performance.now();
  const step = now => { const p = Math.min(1, (now - t0) / ms); el.textContent = Math.round(to * (1 - Math.pow(1 - p, 3))); if (p < 1) requestAnimationFrame(step); };
  requestAnimationFrame(step);
}
export function gauge(score, level) {
  const R = 74, C = 2 * Math.PI * R;
  const col = score >= 80 ? "var(--crit)" : score >= 55 ? "var(--high)" : score >= 30 ? "var(--med)" : "var(--ok)";
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("width", 170); svg.setAttribute("height", 170);
  const mk = (stroke, off) => { const c = document.createElementNS(ns, "circle"); c.setAttribute("cx", 85); c.setAttribute("cy", 85); c.setAttribute("r", R); c.setAttribute("fill", "none"); c.setAttribute("stroke", stroke); c.setAttribute("stroke-width", 12); c.setAttribute("stroke-linecap", "round"); c.setAttribute("stroke-dasharray", C); c.setAttribute("stroke-dashoffset", off); return c; };
  const fg = mk(col, C); fg.style.transition = "stroke-dashoffset 1.2s cubic-bezier(.2,.8,.2,1)";
  svg.append(mk("#ffffff14", 0), fg);
  requestAnimationFrame(() => requestAnimationFrame(() => fg.setAttribute("stroke-dashoffset", C * (1 - score / 100))));
  const n = h("b", null, "0"); countUp(n, score);
  return h("div", { class: "gauge" }, svg, h("div", { class: "c" }, n, h("span", null, level + " risk")));
}
export function sevBars(counts) {
  const max = Math.max(1, ...SEV.map(s => counts[s] || 0));
  return h("div", null, SEV.map(s => h("div", { style: { display: "grid", gridTemplateColumns: "80px 1fr 34px", gap: "10px", alignItems: "center", margin: "7px 0" } },
    h("span", { style: { color: "var(--mut)", fontSize: "12px" } }, s[0] + s.slice(1).toLowerCase()),
    h("div", { class: "bar" }, h("i", { style: { width: "0%", background: SEV_COLOR[s] }, "data-w": ((counts[s] || 0) / max * 100) + "%" })),
    h("b", null, counts[s] || 0))));
}
export function animateBars(root) { requestAnimationFrame(() => requestAnimationFrame(() => root.querySelectorAll("[data-w]").forEach(e => e.style.width = e.dataset.w))); }
export function sparkline(values, color = "var(--teal)") {
  const ns = "http://www.w3.org/2000/svg", W = 300, H = 70;
  const svg = document.createElementNS(ns, "svg"); svg.setAttribute("viewBox", `0 0 ${W} ${H}`); svg.setAttribute("class", "spark"); svg.setAttribute("preserveAspectRatio", "none");
  if (values.length < 2) values = [values[0] ?? 0, values[0] ?? 0];
  const pts = values.map((v, i) => [i / (values.length - 1) * W, H - 6 - v / 100 * (H - 12)]);
  const line = document.createElementNS(ns, "polyline"); line.setAttribute("points", pts.map(p => p.join(",")).join(" ")); line.setAttribute("fill", "none"); line.setAttribute("stroke", color); line.setAttribute("stroke-width", 2.5); line.setAttribute("stroke-linejoin", "round");
  const area = document.createElementNS(ns, "polygon"); area.setAttribute("points", `0,${H} ${pts.map(p => p.join(",")).join(" ")} ${W},${H}`); area.setAttribute("fill", color); area.setAttribute("opacity", .12);
  svg.append(area, line); return svg;
}
export const fmtDate = s => (s || "").replace("T", " ").replace("Z", "");
