// Force-directed attack-surface graph on <canvas>: drag nodes, pan, wheel-zoom, hover tooltips, click to select.
const TYPE_COLOR = { app: "#8b7bff", activity: "#35e0c2", service: "#4cc9f0", receiver: "#ff6ba6", provider: "#ffd23f", "activity-alias": "#35e0c2", deeplink: "#9ef01a", permission: "#8b9ac4" };
const SEV_RING = { CRITICAL: "#ff3b6b", HIGH: "#ff8a3d", MEDIUM: "#ffd23f", LOW: "#4cc9f0" };

export class Graph {
  constructor(canvas, tip, data, onSelect) {
    this.c = canvas; this.tip = tip; this.onSelect = onSelect;
    this.ctx = canvas.getContext("2d");
    this.view = { x: 0, y: 0, k: 1, set: false };
    this.nodes = data.nodes.map((n, i) => ({ ...n, x: Math.cos(i) * (80 + i * 6), y: Math.sin(i) * (80 + i * 6), vx: 0, vy: 0, r: n.type === "app" ? 20 : n.type === "deeplink" ? 9 : n.type === "permission" ? 7 : 12 }));
    const byId = new Map(this.nodes.map(n => [n.id, n]));
    this.edges = data.edges.map(e => ({ ...e, a: byId.get(e.from), b: byId.get(e.to) })).filter(e => e.a && e.b);
    this.nodes[0].x = this.nodes[0].y = 0;
    this.hover = null; this.sel = null; this.drag = null; this.pan = null; this.alpha = 1; this.hidden = new Set();
    this.dpr = window.devicePixelRatio || 1;
    this.bind(); this.resize(); this.running = true; this.t = 0;
    this.loop = this.loop.bind(this); requestAnimationFrame(this.loop);
    this.ro = new ResizeObserver(() => this.resize()); this.ro.observe(canvas);
  }
  destroy() { this.running = false; this.ro.disconnect(); }
  resize() { const r = this.c.getBoundingClientRect(); this.w = r.width; this.h = r.height; this.c.width = r.width * this.dpr; this.c.height = r.height * this.dpr; if (!this.view.set && r.width > 0) { this.view.x = r.width / 2; this.view.y = r.height / 2; this.view.set = true; } }
  toWorld(px, py) { return [(px - this.view.x) / this.view.k, (py - this.view.y) / this.view.k]; }
  pick(px, py) { const [x, y] = this.toWorld(px, py); let best = null; for (const n of this.nodes) { if (this.hidden.has(n.type)) continue; const d = Math.hypot(n.x - x, n.y - y); if (d <= n.r + 4 / this.view.k) best = n; } return best; }
  setHidden(type, off) { off ? this.hidden.add(type) : this.hidden.delete(type); }
  fit() { this.view = { x: this.w / 2, y: this.h / 2, k: 1, set: true }; this.alpha = 1; }
  bind() {
    const c = this.c, pos = e => { const r = c.getBoundingClientRect(); return [e.clientX - r.left, e.clientY - r.top]; };
    c.addEventListener("pointerdown", e => { const [x, y] = pos(e); c.setPointerCapture(e.pointerId); const n = this.pick(x, y); if (n) { this.drag = n; this.moved = false; this.alpha = .6; } else this.pan = { x, y, vx: this.view.x, vy: this.view.y }; });
    c.addEventListener("pointermove", e => {
      const [x, y] = pos(e);
      if (this.drag) { [this.drag.x, this.drag.y] = this.toWorld(x, y); this.drag.vx = this.drag.vy = 0; this.moved = true; this.alpha = .5; }
      else if (this.pan) { this.view.x = this.pan.vx + x - this.pan.x; this.view.y = this.pan.vy + y - this.pan.y; }
      else { const n = this.pick(x, y); if (n !== this.hover) { this.hover = n; c.style.cursor = n ? "pointer" : "grab"; } this.showTip(n, x, y); }
    });
    c.addEventListener("pointerup", () => { if (this.drag && !this.moved) { this.sel = this.drag; this.onSelect?.(this.drag); } else if (this.pan && !this.drag) { /* background click clears */ } this.drag = null; this.pan = null; });
    c.addEventListener("pointerleave", () => { this.hover = null; this.tip.style.display = "none"; });
    c.addEventListener("wheel", e => { e.preventDefault(); const [x, y] = pos(e), k0 = this.view.k, k = Math.min(3, Math.max(.25, k0 * (e.deltaY < 0 ? 1.12 : 1 / 1.12))); this.view.x = x - (x - this.view.x) * k / k0; this.view.y = y - (y - this.view.y) * k / k0; this.view.k = k; }, { passive: false });
  }
  showTip(n, x, y) {
    if (!n) { this.tip.style.display = "none"; return; }
    const m = n.meta || {}; this.tip.replaceChildren();
    const b = document.createElement("b"); b.textContent = n.type === "deeplink" ? n.label : (m.name || n.label); this.tip.append(b);
    const lines = [n.type + (m.guard ? ` · guard ${m.guard}` : ""), n.severity ? `worst finding: ${n.severity}` : null, m.findings ? `${m.findings} finding(s)` : null, m.app_link ? "App Link" + (m.verified ? " (autoVerify)" : "") : null].filter(Boolean);
    for (const l of lines) { const d = document.createElement("div"); d.textContent = l; d.style.color = "var(--mut)"; this.tip.append(d); }
    this.tip.style.display = "block"; this.tip.style.left = Math.min(x + 14, this.w - 350) + "px"; this.tip.style.top = y + 14 + "px";
  }
  step() {
    const N = this.nodes.filter(n => !this.hidden.has(n.type)), a = this.alpha;
    for (let i = 0; i < N.length; i++) for (let j = i + 1; j < N.length; j++) {
      const p = N[i], q = N[j]; let dx = p.x - q.x, dy = p.y - q.y, d2 = dx * dx + dy * dy + .01; if (d2 > 160000) continue;
      const f = 5200 / d2, d = Math.sqrt(d2); dx /= d; dy /= d; p.vx += dx * f * a; p.vy += dy * f * a; q.vx -= dx * f * a; q.vy -= dy * f * a;
    }
    for (const e of this.edges) {
      if (this.hidden.has(e.a.type) || this.hidden.has(e.b.type)) continue;
      const dx = e.b.x - e.a.x, dy = e.b.y - e.a.y, d = Math.hypot(dx, dy) + .01, L = e.kind === "routes" ? 90 : 150, f = (d - L) * .02 * a;
      e.a.vx += dx / d * f; e.a.vy += dy / d * f; e.b.vx -= dx / d * f; e.b.vy -= dy / d * f;
    }
    for (const n of N) { n.vx -= n.x * .004 * a; n.vy -= n.y * .004 * a; if (n === this.drag) continue; n.x += n.vx; n.y += n.vy; n.vx *= .82; n.vy *= .82; }
    this.alpha = Math.max(.02, this.alpha * .992);
  }
  loop() {
    if (!this.running) return;
    this.t += 1; this.step(); this.draw(); requestAnimationFrame(this.loop);
  }
  draw() {
    const g = this.ctx, { x, y, k } = this.view, d = this.dpr;
    g.setTransform(d, 0, 0, d, 0, 0); g.clearRect(0, 0, this.w, this.h);
    g.translate(x, y); g.scale(k, k);
    const focus = this.sel || this.hover, linked = new Set();
    if (focus) { linked.add(focus.id); for (const e of this.edges) { if (e.a === focus) linked.add(e.b.id); if (e.b === focus) linked.add(e.a.id); } }
    for (const e of this.edges) {
      if (this.hidden.has(e.a.type) || this.hidden.has(e.b.type)) continue;
      const on = focus && (e.a === focus || e.b === focus);
      g.globalAlpha = focus ? (on ? .95 : .08) : .35; g.lineWidth = on ? 2 : 1;
      g.strokeStyle = e.kind === "routes" ? "#9ef01a" : e.guard === "none" && e.kind === "exports" ? "#ff8a3d" : "#6b7bb0";
      g.setLineDash(e.kind === "requests" ? [4, 4] : []);
      g.beginPath(); g.moveTo(e.a.x, e.a.y); g.lineTo(e.b.x, e.b.y); g.stroke();
    }
    g.setLineDash([]);
    for (const n of this.nodes) {
      if (this.hidden.has(n.type)) continue;
      g.globalAlpha = focus && !linked.has(n.id) ? .18 : 1;
      const col = TYPE_COLOR[n.type] || "#999";
      if (n.severity) { const pulse = 4 + Math.sin(this.t / 18 + n.x) * 1.5; g.beginPath(); g.arc(n.x, n.y, n.r + pulse, 0, 7); g.strokeStyle = SEV_RING[n.severity]; g.globalAlpha *= .55; g.lineWidth = 2; g.stroke(); g.globalAlpha = focus && !linked.has(n.id) ? .18 : 1; }
      const grad = g.createRadialGradient(n.x - n.r / 3, n.y - n.r / 3, 1, n.x, n.y, n.r); grad.addColorStop(0, "#fff"); grad.addColorStop(.25, col); grad.addColorStop(1, col);
      g.fillStyle = grad; g.beginPath();
      if (n.type === "permission") { g.rect(n.x - n.r, n.y - n.r, n.r * 2, n.r * 2); } else g.arc(n.x, n.y, n.r, 0, 7);
      g.fill();
      if (n === this.sel || n === this.hover) { g.lineWidth = 2.5; g.strokeStyle = "#fff"; g.stroke(); }
      if (k > .55 || n.type === "app" || n === this.hover || linked.has(n.id)) {
        g.fillStyle = getComputedStyle(document.documentElement).getPropertyValue("--txt").trim() || "#fff"; g.font = `${n.type === "app" ? 600 : 400} ${11}px ui-sans-serif,system-ui`; g.textAlign = "center";
        const label = n.label.length > 34 ? n.label.slice(0, 33) + "…" : n.label; g.fillText(label, n.x, n.y + n.r + 14);
      }
    }
    g.globalAlpha = 1;
  }
}
export const GRAPH_LEGEND = Object.entries(TYPE_COLOR).filter(([k]) => k !== "activity-alias");
