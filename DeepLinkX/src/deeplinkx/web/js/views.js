import { api } from "./api.js";
import { h, sev, pill, SEV, SEV_COLOR, toast, gauge, sevBars, animateBars, sparkline, fmtDate, countUp } from "./dom.js";
import { Graph, GRAPH_LEGEND } from "./graph.js";

const STATUSES = ["open", "confirmed", "false_positive", "accepted", "fixed"];
const short = n => (n || "").split(".").slice(-1)[0];
const go = hash => { location.hash = hash; };

// ------------------------------------------------------------------ upload
function uploader(info) {
  const input = h("input", { type: "file", accept: ".apk,.zip,application/vnd.android.package-archive", hidden: true, multiple: true });
  const profile = h("select", null, (info.profiles || ["standard"]).map(p => h("option", { value: p, selected: p === "standard" }, p)));
  const al = h("input", { type: "checkbox", id: "al" });
  const queue = h("div", { style: { marginTop: "16px", display: "grid", gap: "12px" } });
  const drop = h("div", { class: "drop", tabindex: 0, role: "button", onclick: () => input.click(), onkeydown: e => (e.key === "Enter" || e.key === " ") && input.click() },
    h("big", null, "⇪"), h("b", null, "Drop APK files here"), h("div", null, "or click to browse · analysed locally on this server · max " + info.max_upload_mb + " MB"));
  const run = files => [...files].forEach(f => start(f));
  async function start(file) {
    const bar = h("i"), stage = h("div", { class: "stage" }, "uploading…");
    const row = h("div", { class: "card", style: { padding: "14px" } }, h("div", { style: { display: "flex", justifyContent: "space-between" } }, h("b", null, file.name), h("span", { class: "mono", style: { color: "var(--mut)" } }, (file.size / 1024).toFixed(0) + " KB")), h("div", { class: "progress", style: { marginTop: "10px" } }, bar), stage);
    queue.prepend(row);
    try {
      const job = await api.upload(file, profile.value, al.checked);
      const es = new EventSource(api.eventsUrl(job.id));
      es.addEventListener("progress", e => { const d = JSON.parse(e.data); bar.style.width = Math.round(d.fraction * 100) + "%"; stage.textContent = `${d.stage} — ${d.message}`; });
      es.addEventListener("end", e => {
        es.close(); const d = JSON.parse(e.data);
        if (d.state === "done") { bar.style.width = "100%"; stage.textContent = "done"; toast(file.name + " analysed"); setTimeout(() => go("#/scan/" + d.scan_id), 500); }
        else { stage.textContent = "failed: " + d.error; row.style.borderColor = "var(--crit)"; toast(d.error, true); }
      });
      es.onerror = () => { es.close(); };
    } catch (err) { stage.textContent = "failed: " + err.message; row.style.borderColor = "var(--crit)"; toast(err.message, true); }
  }
  input.addEventListener("change", () => { run(input.files); input.value = ""; });
  ["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", e => run(e.dataTransfer.files));
  return h("div", { class: "card" }, h("h2", null, "New scan"),
    h("div", { class: "toolbar" }, h("label", null, "Profile ", profile), h("label", { for: "al", style: { color: "var(--mut)" } }, al, " verify App Links (network)")),
    drop, input, queue);
}

// ------------------------------------------------------------------ home
export async function home(root) {
  const [info, scans] = await Promise.all([api.info(), api.scans()]);
  const latest = scans[0];
  const pkgs = new Set(scans.map(s => s.package));
  const stat = (label, val) => { const v = h("div", { class: "v" }, "0"); countUp(v, val); return h("div", { class: "card stat" }, v, h("div", { class: "l" }, label)); };
  const sum = k => scans.reduce((a, s) => a + (s.counts[k] || 0), 0);
  root.append(h("h1", null, "Attack surface, mapped."), h("p", { class: "sub" }, "Static and dynamic assessment of Android deep links and externally reachable entry points."),
    h("div", { class: "grid g4" }, stat("scans", scans.length), stat("applications", pkgs.size), stat("high+ findings (all scans)", sum("CRITICAL") + sum("HIGH")), stat("latest risk", latest ? latest.risk : 0)),
    h("div", { class: "grid g2", style: { marginTop: "18px" } }, uploader(info), recentCard(scans.slice(0, 6))));
}
function recentCard(scans) {
  return h("div", { class: "card" }, h("h2", null, "Recent scans"), scans.length ? h("table", null, scans.map(s => h("tr", { class: "click", onclick: () => go("#/scan/" + s.id) },
    h("td", null, h("b", null, s.package), h("div", { style: { color: "var(--dim)", fontSize: "12px" } }, fmtDate(s.created))), h("td", null, h("b", { style: { color: s.risk >= 80 ? "var(--crit)" : s.risk >= 55 ? "var(--high)" : "var(--ok)" } }, s.risk)),
    h("td", null, SEV.slice(0, 3).map(k => s.counts[k] ? h("span", { class: "sev " + k, style: { marginRight: "4px", minWidth: "0" } }, s.counts[k]) : null))))) : h("div", { class: "empty" }, "No scans yet — drop an APK to begin."));
}

// ------------------------------------------------------------------ history
export async function history(root) {
  const scans = await api.scans(); const picked = [];
  const cmp = h("button", { class: "btn sm", disabled: true, onclick: () => go(`#/diff/${picked[0]}/${picked[1]}`) }, "Compare selected (2)");
  root.append(h("h1", null, "Scan history"), h("p", { class: "sub" }, "Stored locally. Select two scans of the same app to compare."), h("div", { class: "toolbar" }, cmp));
  if (!scans.length) { root.append(h("div", { class: "card empty" }, "No scans recorded yet.")); return; }
  root.append(h("div", { class: "card" }, h("table", null, h("thead", null, h("tr", null, ["", "ID", "When (UTC)", "Package", "Version", "Risk", "C", "H", "M", "L", ""].map(x => h("th", null, x)))),
    h("tbody", null, scans.map(s => h("tr", { class: "click", onclick: e => { if (e.target.closest("button,input")) return; go("#/scan/" + s.id); } },
      h("td", null, h("input", { type: "checkbox", onchange: e => { if (e.target.checked) picked.push(s.id); else picked.splice(picked.indexOf(s.id), 1); while (picked.length > 2) { picked.shift(); } cmp.disabled = picked.length !== 2; } })),
      h("td", { class: "mono" }, "#" + s.id), h("td", null, fmtDate(s.created)), h("td", null, h("b", null, s.package)), h("td", null, s.version), h("td", null, h("b", null, s.risk)),
      ...["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(k => h("td", null, s.counts[k] || 0)),
      h("td", null, h("button", { class: "btn ghost sm", onclick: async () => { if (confirm("Delete scan #" + s.id + "?")) { await api.del(s.id); toast("deleted"); route(); } } }, "Delete"))))))));
}
const route = () => window.dispatchEvent(new HashChangeEvent("hashchange"));

// ------------------------------------------------------------------ scan detail
export async function scanView(root, id, tabName) {
  const rep = await api.scan(id);
  const apk = rep.apk, sum = rep.summary;
  const trend = await api.trend(apk.package).catch(() => []);
  const tabs = {
    overview: () => overview(rep, trend), findings: () => findings(rep), links: () => links(rep), entry: () => entries(rep),
    graph: () => graphTab(id), perms: () => perms(rep), dynamic: () => dynamic(rep),
  };
  const counts = { findings: sum.active, links: rep.deep_links.length, entry: rep.entry_points.length };
  const labels = { overview: "Overview", findings: "Findings", links: "Deep links", entry: "Entry points", graph: "Graph", perms: "Permissions & config", dynamic: "Dynamic" };
  const body = h("div");
  const bar = h("div", { class: "tabs", role: "tablist" }, Object.keys(tabs).map(k => h("button", { role: "tab", class: k === tabName ? "on" : "", onclick: () => go(`#/scan/${id}/${k}`) }, labels[k], counts[k] != null ? h("span", { class: "n" }, counts[k]) : null)));
  const dl = fmt => h("a", { class: "btn ghost sm", href: api.reportUrl(id, fmt, true) }, fmt.toUpperCase());
  root.append(h("div", { style: { display: "flex", gap: "16px", alignItems: "flex-start", flexWrap: "wrap" } },
    h("div", { style: { flex: 1, minWidth: "260px" } }, h("h1", null, apk.package), h("p", { class: "sub", style: { margin: 0 } }, `${apk.app_label || ""} · v${apk.version_name} (${apk.version_code}) · scan #${id} · ${fmtDate(rep.meta.created)} · profile ${rep.meta.profile}`)),
    h("div", { class: "toolbar" }, h("a", { class: "btn sm", href: api.reportUrl(id, "html"), target: "_blank", rel: "noopener" }, "Open report"), dl("html"), dl("pdf"), dl("json"), dl("sarif"))), bar, body);
  const mount = tabs[tabName] || tabs.overview;
  body.append(await mount());
  animateBars(body);
}

function overview(rep, trend) {
  const apk = rep.apk, sum = rep.summary, ex = rep.exposure || {};
  const flags = [apk.debuggable && pill("debuggable", "bad"), apk.allow_backup && pill("allowBackup", "warn"), apk.uses_cleartext && pill("cleartext", "warn"), !apk.signing.signed && pill("unsigned", "bad"),
    ...Object.entries(apk.signing.schemes).filter(([, v]) => v).map(([k]) => pill(k, "ok"))];
  const kv = (rows) => h("dl", { class: "kv" }, rows.flatMap(([k, v]) => [h("dt", null, k), h("dd", { class: "mono" }, v)]));
  return h("div", { class: "grid g2" },
    h("div", { class: "card", style: { textAlign: "center" } }, gauge(sum.risk_score, sum.risk_level), h("div", { style: { marginTop: "14px" } }, flags)),
    h("div", { class: "card" }, h("h2", null, "Findings by severity"), sevBars(sum.by_severity), h("div", { style: { color: "var(--mut)", marginTop: "8px", fontSize: "13px" } }, `${sum.active} active of ${sum.total} total`)),
    h("div", { class: "card" }, h("h2", null, "Application"), kv([["SDK", `min ${apk.min_sdk} · target ${apk.target_sdk}`], ["Size", apk.size.toLocaleString() + " bytes"], ["SHA-256", apk.hashes.sha256], ["DEX", apk.dex_files.join(", ")], ["Signer", (apk.signing.certificates[0] || {}).subject || "—"]])),
    h("div", { class: "card" }, h("h2", null, "Exposure"), kv([["Deep links", `${rep.link_summary.total} (${rep.link_summary.app_links} app links, ${rep.link_summary.custom_scheme} custom)`], ["Exported", `${rep.entry_points.length} entry points`], ["Unprotected", rep.entry_points.filter(e => e.guard === "none").length], ["Rules run", rep.meta.rules_run]])),
    h("div", { class: "card" }, h("h2", null, "Risk over time"), sparkline(trend.map(t => t.risk)), h("div", { style: { color: "var(--mut)", fontSize: "12px" } }, `${trend.length} scan(s) of this app`)),
    h("div", { class: "card" }, h("h2", null, "By category"), h("div", null, Object.entries(sum.by_category).sort((a, b) => b[1] - a[1]).map(([k, v]) => pill(`${k} · ${v}`)))),
    rep.diff ? h("div", { class: "card" }, h("h2", null, "Since previous scan"), h("div", null, h("b", { class: "diffnew" }, "+" + rep.diff.new.length), " new · ", h("b", { class: "diffres" }, "−" + rep.diff.resolved.length), " resolved")) : null);
}

function findings(rep) {
  const list = h("div"), q = h("input", { type: "search", placeholder: "filter findings…", style: { minWidth: "240px" } });
  const sevSel = h("select", null, h("option", { value: "" }, "all severities"), SEV.map(s => h("option", { value: s }, s)));
  const stSel = h("select", null, h("option", { value: "active" }, "active"), h("option", { value: "all" }, "all"), STATUSES.map(s => h("option", { value: s }, s)));
  const count = h("span", { style: { color: "var(--mut)" } });
  const render = () => {
    const t = q.value.toLowerCase();
    const items = rep.findings.filter(f => (!sevSel.value || f.severity === sevSel.value) && (stSel.value === "all" || (stSel.value === "active" ? ["open", "confirmed"].includes(f.status) : f.status === stSel.value)) &&
      (!t || [f.title, f.component, f.rule_id, f.category, f.description].join(" ").toLowerCase().includes(t)));
    count.textContent = `${items.length} shown`; list.replaceChildren(...items.map(finding(rep)));
    if (!items.length) list.append(h("div", { class: "empty" }, "No findings match."));
  };
  [q, sevSel, stSel].forEach(e => e.addEventListener("input", render)); render();
  return h("div", null, h("div", { class: "toolbar" }, q, sevSel, stSel, h("span", { class: "sp" }), count), list);
}
const finding = rep => f => {
  const el = h("div", { class: `finding ${f.severity}${["false_positive", "fixed", "accepted"].includes(f.status) ? " fp" : ""}`, id: f.id });
  const section = (t, c) => c && (Array.isArray(c) ? c.length : true) ? [h("h4", null, t), c] : [];
  const st = h("select", { onchange: async e => { try { await api.status(rep.apk.package, f.id, e.target.value); toast(`${f.id} → ${e.target.value}`); el.classList.toggle("fp", ["false_positive", "fixed", "accepted"].includes(e.target.value)); } catch (err) { toast(err.message, true); } } }, STATUSES.map(s => h("option", { value: s, selected: s === f.status }, s)));
  el.append(h("div", { class: "f-head", onclick: e => { if (!e.target.closest("select")) el.classList.toggle("open"); } }, sev(f.severity), h("h3", null, f.title), h("span", { class: "mono", style: { color: "var(--dim)", fontSize: "12px" } }, `${f.id} · ${f.rule_id}`)),
    h("div", { style: { marginTop: "6px", color: "var(--mut)", fontSize: "13px" } }, f.component ? short(f.component) + " · " : "", f.category, " · confidence ", f.confidence.toLowerCase(), f.occurrences > 1 ? ` · ×${f.occurrences}` : ""),
    h("div", { class: "f-body" }, section("Explanation", h("p", null, f.description)), section("Impact", f.impact && h("p", null, f.impact)),
      section("Evidence", f.evidence.map(ev => h("div", null, h("div", { style: { color: "var(--mut)", fontSize: "12px" } }, `${ev.kind} · ${ev.title}`), h("pre", null, ev.content)))),
      section("Reproduction", f.reproduction.length && h("pre", null, f.reproduction.join("\n"))), section("Remediation", f.remediation && h("p", null, f.remediation)),
      section("References", f.references.map(r => h("div", null, /^https?:/.test(r) ? h("a", { href: r, target: "_blank", rel: "noopener noreferrer" }, r) : r))),
      h("div", { class: "toolbar", style: { marginTop: "14px" } }, h("span", { style: { color: "var(--mut)" } }, "Status"), st, f.tags.map(t => pill(t)))));
  return el;
};

function table(head, rows) { return h("div", { class: "card", style: { overflowX: "auto" } }, h("table", null, h("thead", null, h("tr", null, head.map(x => h("th", null, x)))), h("tbody", null, rows))); }
function links(rep) {
  if (!rep.deep_links.length) return h("div", { class: "card empty" }, "No deep links declared.");
  return table(["URI", "Component", "Type", "Browsable", "Verified", "Permission"], rep.deep_links.map(d => h("tr", null, h("td", { class: "mono" }, d.uri), h("td", null, short(d.component)), h("td", null, pill(d.is_app_link ? "app link" : d.scheme === "http" || d.scheme === "https" ? "web" : "custom", d.is_app_link ? "ok" : "warn")), h("td", null, d.browsable ? "yes" : "no"), h("td", null, d.auto_verify ? "autoVerify" : "—"), h("td", null, d.permission || "—"))));
}
function entries(rep) {
  const col = { none: "bad", weak: "warn", medium: "", strong: "ok" };
  return table(["Component", "Kind", "Guard", "Why exposed", "Notes"], rep.entry_points.map(e => h("tr", null, h("td", null, h("b", null, short(e.name)), h("div", { class: "mono", style: { color: "var(--dim)", fontSize: "11px" } }, e.name)), h("td", null, e.kind), h("td", null, pill(e.guard, col[e.guard] || "")), h("td", null, e.reasons.join("; ")), h("td", { style: { color: "var(--mut)" } }, [e.is_launcher && "launcher", ...e.unintended].filter(Boolean).join("; ")))));
}
function perms(rep) {
  const p = rep.permissions, n = rep.network_security || {};
  return h("div", { class: "grid g2" },
    h("div", { class: "card" }, h("h2", null, "Requested permissions"), p.requested.map(x => pill(x.replace("android.permission.", ""), p.dangerous.includes(x) ? "bad" : p.high_impact.includes(x) ? "warn" : ""))),
    h("div", { class: "card" }, h("h2", null, "Custom permissions"), p.custom_declared.length ? p.custom_declared.map(c => pill(`${c.name} · ${c.protection}`, p.weak_custom.includes(c.name) ? "bad" : "ok")) : "none declared"),
    h("div", { class: "card" }, h("h2", null, "Network security config"), n.present ? h("div", null, pill(n.base_cleartext ? "cleartext allowed" : "cleartext blocked", n.base_cleartext ? "bad" : "ok"), pill(n.user_certs_trusted ? "user CAs trusted" : "system CAs only", n.user_certs_trusted ? "warn" : "ok"), pill(`${n.pins} pin(s)`), n.debug_overrides && pill("debug-overrides", "warn"), n.domain_configs.map(d => h("div", { class: "mono", style: { marginTop: "8px" } }, d.domains.map(x => x.name).join(", "), " ", d.pinned ? pill("pinned", "ok") : null, d.cleartext ? pill("cleartext", "bad") : null))) : "No network security configuration."),
    h("div", { class: "card" }, h("h2", null, "Digital Asset Links"), (rep.assetlinks && rep.assetlinks.results && rep.assetlinks.results.length) ? rep.assetlinks.results.map(r => h("div", null, pill(r.status || r.state || "?", r.status === "verified" ? "ok" : "warn"), " ", r.host)) : "Not checked. Enable “verify App Links” when scanning."));
}
function dynamic(rep) {
  const d = rep.dynamic;
  if (!d) return h("div", { class: "card" }, h("h2", null, "No dynamic run"), h("p", { style: { color: "var(--mut)" } }, "Dynamic testing needs an emulator and explicit authorisation, so it is started from the CLI:"), h("pre", null, `deeplinkx scan app.apk --dynamic --authorized --install\ndeeplinkx dynamic app.apk --plan-only   # preview test cases only`));
  return h("div", { class: "card" }, h("h2", null, "Dynamic run"), h("pre", null, JSON.stringify({ device: d.device, cases: (d.results || []).length, confirmed_static: d.confirmed_static, new_findings: d.new_findings }, null, 2)));
}
async function graphTab(id) {
  const data = await api.graph(id);
  const canvas = h("canvas"), tip = h("div", { id: "tip" }), side = h("div", { style: { position: "absolute", right: "12px", bottom: "12px", maxWidth: "280px" } });
  const wrap = h("div", { id: "graphwrap" }, canvas, tip, side);
  const legend = h("div", { class: "legend" }, GRAPH_LEGEND.map(([k, c]) => h("label", { style: { cursor: "pointer" } }, h("input", { type: "checkbox", checked: true, style: { display: "none" }, onchange: e => { g.setHidden(k, !e.target.checked); g.alpha = 1; e.target.parentElement.style.opacity = e.target.checked ? 1 : .35; } }), h("i", { style: { background: c } }), k)));
  wrap.append(legend, h("div", { class: "gctl" }, h("button", { class: "btn ghost sm", onclick: () => g.fit() }, "Reset view")));
  const g = new Graph(canvas, tip, data, n => { side.replaceChildren(h("div", { class: "card", style: { padding: "12px", fontSize: "13px" } }, h("b", null, n.meta.name || n.label), h("div", { style: { color: "var(--mut)" } }, n.type), n.severity ? sev(n.severity) : null)); });
  window.__graph = g; const stop = () => { g.destroy(); window.removeEventListener("hashchange", stop); }; window.addEventListener("hashchange", stop);
  return h("div", null, h("p", { class: "sub" }, "Drag nodes, scroll to zoom, drag background to pan. Orange edges are unprotected exports; green edges are deep link routes. Pulsing rings mark components with findings."), wrap);
}

// ------------------------------------------------------------------ diff
export async function diffView(root, a, b) {
  const d = await api.diff(a, b);
  const list = (items, cls) => items.length ? items.map(f => h("tr", null, h("td", null, sev(f.severity)), h("td", null, f.title), h("td", { class: "mono" }, short(f.component || "app")))) : [h("tr", null, h("td", { colspan: 3, style: { color: "var(--dim)" } }, "none"))];
  root.append(h("h1", null, `Scan #${a} → #${b}`), h("p", { class: "sub" }, `Risk ${d.risk_before} → ${d.risk_after}`),
    h("div", { class: "grid g2" }, h("div", { class: "card" }, h("h2", { class: "diffnew" }, `New (${d.new.length})`), h("table", null, list(d.new))), h("div", { class: "card" }, h("h2", { class: "diffres" }, `Resolved (${d.resolved.length})`), h("table", null, list(d.resolved)))));
}

// ------------------------------------------------------------------ rules / about
export async function rulesView(root) {
  const rules = await api.rules(); const q = h("input", { type: "search", placeholder: "filter rules…" }); const tb = h("tbody");
  const render = () => { const t = q.value.toLowerCase(); tb.replaceChildren(...rules.filter(r => !t || (r.id + r.title + r.category + r.description).toLowerCase().includes(t)).map(r => h("tr", null, h("td", { class: "mono" }, r.id), h("td", null, sev(r.severity)), h("td", null, r.category), h("td", null, h("b", null, r.title), h("div", { style: { color: "var(--mut)", fontSize: "13px" } }, r.description)), h("td", null, r.source)))); };
  q.addEventListener("input", render); render();
  root.append(h("h1", null, "Rules"), h("p", { class: "sub" }, `${rules.length} rules loaded — built-in, YAML and plugin rules.`), h("div", { class: "toolbar" }, q), h("div", { class: "card", style: { overflowX: "auto" } }, h("table", null, h("thead", null, h("tr", null, ["ID", "Severity", "Category", "Rule", "Source"].map(x => h("th", null, x)))), tb)));
}
export async function about(root) {
  const info = await api.info();
  root.append(h("h1", null, "DEEPLINK X"), h("p", { class: "sub" }, info.tagline), h("div", { class: "card" }, h("p", null, `Version ${info.version}. Open-source Android app security assessment tool by Karndeep Baror.`),
    h("p", null, h("a", { href: "https://github.com/karndeepbaror", target: "_blank", rel: "noopener" }, "github.com/karndeepbaror"), " · ", h("a", { href: "https://x.com/karndeepbaror", target: "_blank", rel: "noopener" }, "x.com/karndeepbaror")),
    h("p", { style: { color: "var(--mut)" } }, "Dynamic testing is intended only for applications you own or are explicitly authorised to test, in isolated environments. Data directory: ", h("code", null, info.home))));
}
