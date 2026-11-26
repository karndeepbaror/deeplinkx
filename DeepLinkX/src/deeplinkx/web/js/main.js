import { api, setToken, ApiError } from "./api.js";
import { h, toast } from "./dom.js";
import * as V from "./views.js";

const view = document.getElementById("view");
try { const t = localStorage.getItem("dlx-theme"); if (t) document.documentElement.dataset.theme = t; } catch {}
document.getElementById("theme").onclick = () => {
  const n = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = n; try { localStorage.setItem("dlx-theme", n); } catch {}
};

async function askToken() {
  const dlg = document.getElementById("auth"), inp = document.getElementById("token");
  if (dlg.open) return;
  await new Promise(res => { dlg.addEventListener("close", res, { once: true }); dlg.showModal(); });
  setToken(inp.value.trim());
}

async function render() {
  const [, page = "", a, b, c] = location.hash.slice(1).split("/");
  document.querySelectorAll("nav a").forEach(x => x.classList.toggle("on", x.dataset.nav === (page === "" ? "home" : page === "scan" || page === "diff" ? "scans" : page)));
  view.replaceChildren(h("div", { class: "empty" }, "Loading…"));
  const root = h("div");
  try {
    if (page === "") await V.home(root);
    else if (page === "scans") await V.history(root);
    else if (page === "scan") await V.scanView(root, a, b || "overview");
    else if (page === "diff") await V.diffView(root, a, b);
    else if (page === "rules") await V.rulesView(root);
    else if (page === "about") await V.about(root);
    else root.append(h("div", { class: "empty" }, "Page not found."));
    view.replaceChildren(root); window.scrollTo(0, 0);
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) { await askToken(); return render(); }
    view.replaceChildren(h("div", { class: "card empty" }, h("h2", null, err instanceof ApiError && err.status === 404 ? "Not found" : "Something went wrong"), err.message));
    console.error(err);
  }
}
window.addEventListener("hashchange", render);
render();
