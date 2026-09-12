const API = "/api";
const MODULE_LABELS = {
  subdomains: "Subdomain recon",
  portscan: "Port scan",
  headers: "Headers / misconfig",
  exposure: "Sensitive file exposure",
  sqli: "SQL injection",
  xss: "XSS",
  components: "Vulnerable components",
  access_control: "IDOR / access control",
  ssrf_redirect: "SSRF / open redirect",
};

let state = { targets: [], scans: [], modules: [], pollTimer: null };

function $(sel) { return document.querySelector(sel); }
function esc(s) {
  return (s ?? "").toString().replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

async function api(path, opts) {
  const r = await fetch(API + path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  const data = await r.json().catch(() => null);
  if (!r.ok) throw new Error((data && data.detail) || r.statusText);
  return data;
}

// --- Tabs ---
document.querySelectorAll(".tabbar button").forEach((btn) => {
  btn.addEventListener("click", () => switchView(btn.dataset.view));
});

function switchView(name) {
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  document.querySelectorAll(".tabbar button").forEach((b) => b.classList.remove("active"));
  $("#view-" + name).classList.add("active");
  document.querySelector(`.tabbar button[data-view="${name}"]`).classList.add("active");
  if (name === "scan") refreshScans();
  if (name === "findings") refreshFindingsScanOptions();
}

// --- Targets ---
async function loadTargets() {
  state.targets = await api("/targets");
  renderTargets();
  renderTargetSelect();
}

function renderTargets() {
  const el = $("#targets-list");
  if (!state.targets.length) {
    el.innerHTML = '<div class="empty">No targets yet. Add one above to get started.</div>';
    return;
  }
  el.innerHTML = state.targets.map((t) => `
    <div class="target-item">
      <div class="row">
        <h4>${esc(t.name)}</h4>
        <span class="tag">${t.authorized ? "authorized" : "not authorized"}</span>
      </div>
      <div class="domain">${esc(t.domain)}</div>
      ${t.notes ? `<div style="font-size:12px;color:var(--muted);margin-top:6px;">${esc(t.notes)}</div>` : ""}
      <div style="margin-top:10px;display:flex;gap:8px;">
        <button class="btn small secondary" onclick="deleteTarget(${t.id})">Delete</button>
      </div>
    </div>
  `).join("");
}

function renderTargetSelect() {
  const sel = $("#s-target");
  sel.innerHTML = state.targets.map((t) => `<option value="${t.id}">${esc(t.name)} (${esc(t.domain)})</option>`).join("");
}

window.deleteTarget = async function (id) {
  if (!confirm("Delete this target and its scans?")) return;
  await api(`/targets/${id}`, { method: "DELETE" });
  await loadTargets();
};

$("#btn-add-target").addEventListener("click", async () => {
  const payload = {
    name: $("#t-name").value.trim(),
    domain: $("#t-domain").value.trim(),
    program_url: $("#t-program").value.trim(),
    authorized: $("#t-authorized").checked,
    notes: $("#t-notes").value.trim(),
  };
  if (!payload.name || !payload.domain) return alert("Name and domain are required.");
  if (!payload.authorized) return alert("You must confirm authorization to add a target.");
  try {
    await api("/targets", { method: "POST", body: JSON.stringify(payload) });
    $("#t-name").value = "";
    $("#t-domain").value = "";
    $("#t-program").value = "";
    $("#t-notes").value = "";
    $("#t-authorized").checked = false;
    await loadTargets();
    switchView("scan");
  } catch (e) {
    alert("Error: " + e.message);
  }
});

// --- Scan modules ---
async function loadModules() {
  state.modules = await api("/modules");
  $("#s-modules").innerHTML = state.modules.map((m) => `
    <label>
      <input type="checkbox" value="${m}" checked />
      ${MODULE_LABELS[m] || m}
    </label>
  `).join("");
}

$("#btn-discover").addEventListener("click", async () => {
  const targetId = parseInt($("#s-target").value, 10);
  const baseUrl = $("#s-url").value.trim() || (state.targets.find((t) => t.id === targetId) || {}).domain;
  if (!targetId) return alert("Add and select a target first.");
  if (!baseUrl) return alert("Enter a URL or pick a target with a domain first.");
  const url = baseUrl.startsWith("http") ? baseUrl : `https://${baseUrl}`;

  const statusEl = $("#discover-status");
  const resultsEl = $("#discover-results");
  statusEl.textContent = "Crawling site for parameterized URLs… this can take up to a minute.";
  resultsEl.innerHTML = "";
  $("#btn-discover").disabled = true;
  try {
    const result = await api("/discover", {
      method: "POST",
      body: JSON.stringify({ target_id: targetId, base_url: url }),
    });
    statusEl.textContent = `Crawled ${result.pages_crawled} page(s), found ${result.parameterized_urls.length} URL(s) with parameters.`;
    if (!result.parameterized_urls.length) {
      resultsEl.innerHTML = '<div class="empty">No parameterized URLs found. The site may be a single-page app, or you can enter a URL manually.</div>';
    } else {
      resultsEl.innerHTML = result.parameterized_urls.map((u) => `
        <div class="discover-item" onclick="pickDiscovered('${u.replace(/'/g, "\\'")}')">${esc(u)}</div>
      `).join("");
    }
  } catch (e) {
    statusEl.textContent = "Error: " + e.message;
  } finally {
    $("#btn-discover").disabled = false;
  }
});

window.pickDiscovered = function (url) {
  $("#s-url").value = url;
  window.scrollTo({ top: $("#s-url").getBoundingClientRect().top + window.scrollY - 80, behavior: "smooth" });
};

$("#btn-start-scan").addEventListener("click", async () => {
  const targetId = parseInt($("#s-target").value, 10);
  const url = $("#s-url").value.trim();
  const modules = [...document.querySelectorAll("#s-modules input:checked")].map((i) => i.value);
  if (!targetId) return alert("Add and select a target first.");
  if (!url) return alert("Enter a URL to test.");
  if (!modules.length) return alert("Select at least one module.");
  try {
    await api("/scans", {
      method: "POST",
      body: JSON.stringify({ target_id: targetId, url, modules }),
    });
    await refreshScans();
  } catch (e) {
    alert("Error: " + e.message);
  }
});

async function refreshScans() {
  state.scans = await api("/scans");
  renderScans();
  const hasRunning = state.scans.some((s) => s.status === "running" || s.status === "queued");
  clearTimeout(state.pollTimer);
  if (hasRunning) state.pollTimer = setTimeout(refreshScans, 3000);
}

function renderScans() {
  const el = $("#scans-list");
  if (!state.scans.length) {
    el.innerHTML = '<div class="empty">No scans yet.</div>';
    return;
  }
  el.innerHTML = state.scans.slice(0, 15).map((s) => `
    <div class="target-item">
      <div class="row">
        <div style="font-size:13px;word-break:break-all;max-width:70%;">${esc(s.url)}</div>
        <span class="status-pill ${s.status}">${s.status === "running" ? '<span class="spinner"></span>' : ""}${esc(s.status)}</span>
      </div>
      <div style="font-size:11.5px;color:var(--muted);margin-top:4px;">${esc(s.progress || "")}</div>
      <div style="margin-top:8px;">
        <button class="btn small" onclick="viewFindings(${s.id})">View findings</button>
      </div>
    </div>
  `).join("");
}

window.viewFindings = function (scanId) {
  switchView("findings");
  setTimeout(() => {
    $("#f-scan").value = scanId;
    loadFindings(scanId);
  }, 0);
};

async function refreshFindingsScanOptions() {
  if (!state.scans.length) state.scans = await api("/scans");
  $("#f-scan").innerHTML = state.scans.map((s) => `<option value="${s.id}">#${s.id} - ${esc(s.url)} (${s.status})</option>`).join("");
  if (state.scans.length) loadFindings(state.scans[0].id);
}

$("#f-scan").addEventListener("change", (e) => loadFindings(parseInt(e.target.value, 10)));

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

async function loadFindings(scanId) {
  if (!scanId) return;
  const findings = await api(`/scans/${scanId}/findings`);
  findings.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  const el = $("#findings-list");
  if (!findings.length) {
    el.innerHTML = '<div class="empty">No findings yet (or scan still running).</div>';
    return;
  }
  el.innerHTML = findings.map((f) => `
    <div class="finding ${esc(f.severity)}">
      <div class="top-row">
        <div class="title">${esc(f.title)}</div>
        <span class="sev">${esc(f.severity)}</span>
      </div>
      <div class="cat">${esc(f.category)} · confidence: ${esc(f.confidence)}</div>
      <div class="field-label">Location</div>
      <pre>${esc(f.location)}</pre>
      ${f.evidence ? `<div class="field-label">Evidence</div><pre>${esc(f.evidence)}</pre>` : ""}
      ${f.poc ? `<div class="field-label">Proof of concept</div><pre>${esc(f.poc)}</pre>` : ""}
      ${f.remediation ? `<div class="field-label">Remediation</div><pre>${esc(f.remediation)}</pre>` : ""}
    </div>
  `).join("");
}

async function loadManualChecklist() {
  const items = await api("/manual-checklist");
  $("#manual-checklist").innerHTML = items.map((i) => `
    <div class="checklist-item"><b>${esc(i.category)}</b>${esc(i.note)}</div>
  `).join("");
}

// --- Init ---
(async function init() {
  await Promise.all([loadTargets(), loadModules(), loadManualChecklist()]);
  await refreshScans();

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  }
})();
