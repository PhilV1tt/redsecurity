"use strict";

const SEV = {
  CRIT: { cls: "crit", label: "Critical", dist: "Critical", glyph: "✕", fg: "#b3261e", tone: "rgba(179,38,30,0.18)" },
  WARN: { cls: "warn", label: "Warning", dist: "Warning", glyph: "!", fg: "#8a5a00", tone: "rgba(138,90,0,0.18)" },
  INFO: { cls: "info", label: "Info", dist: "Info", glyph: "i", fg: "#1d63a8", tone: "rgba(29,99,168,0.18)" },
  OK: { cls: "ok", label: "OK", dist: "OK", glyph: "✓", fg: "#1f7a3d", tone: "rgba(31,122,61,0.18)" },
  SKIP: { cls: "skip", label: "Skipped", dist: "Skipped", glyph: "–", fg: "#5d6571", tone: "rgba(93,101,113,0.18)" }
};
const STATUS_ORDER = { CRIT: 0, WARN: 1, INFO: 2, OK: 3, SKIP: 4 };
const DIST_ORDER = ["CRIT", "WARN", "INFO", "OK", "SKIP"];

const CONTROLS = [
  { name: "Open ports", desc: "Listening TCP ports and risky services (RDP, SMB, SSH, VNC, databases).", platform: "All" },
  { name: "Firewall", desc: "Local firewall state and profiles.", platform: "All" },
  { name: "Updates", desc: "Freshness of system and software updates.", platform: "All" },
  { name: "Accounts", desc: "Administrators, guest access, accounts without a password.", platform: "All" },
  { name: "Password policy", desc: "Minimum length and expiry, where readable.", platform: "Win · Linux" },
  { name: "Shared folders", desc: "SMB, NFS or non-standard system shares.", platform: "All" },
  { name: "Startup programs", desc: "Startup entries; temporary paths are flagged.", platform: "All" },
  { name: "Protection", desc: "Antivirus or native protection and signature freshness.", platform: "All" },
  { name: "Disk encryption", desc: "BitLocker, FileVault or LUKS state.", platform: "All" },
  { name: "Hardening", desc: "UAC on Windows; Gatekeeper and SIP on macOS.", platform: "Win · macOS" }
];

const NAV = [
  { key: "home", label: "Home" },
  { key: "overview", label: "Overview" },
  { key: "categories", label: "Categories" },
  { key: "fixes", label: "Issues", badge: true },
  { key: "report", label: "Report" }
];

const NUM = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"];

const state = {
  screen: "home",
  results: null,
  error: "",
  reportFormat: "html",
  exported: false,
  checksDone: 0,
  pending: null
};

const app = document.getElementById("app");
let scanTimer = null;

function render() {
  app.innerHTML = `
    <div class="bs-root" data-screen="${state.screen}">
      <div class="bs-halos" aria-hidden="true">
        <div class="bs-halo a"></div><div class="bs-halo b"></div><div class="bs-halo c"></div>
      </div>
      ${renderTitlebar()}
      <div class="bs-shell">
        ${renderRail()}
        <main class="bs-main">
          ${renderHeader()}
          <div class="bs-content">${renderScreen()}</div>
        </main>
      </div>
    </div>`;
  bindEvents();
}

function renderTitlebar() {
  return `
    <div class="bs-titlebar">
      <div class="bs-mark" aria-hidden="true">✓</div>
      <span class="bs-wordmark">BeSecured</span>
      <div class="bs-spacer"></div>
      <div class="bs-offline"><span class="dot"></span>Offline</div>
    </div>`;
}

function renderRail() {
  const data = state.results;
  const machine = readMachine(data);
  const health = railHealth(data);
  const nav = NAV.map((item) => {
    const active =
      state.screen === item.key ||
      (state.screen === "scanning" && item.key === "overview");
    const count = item.badge && data ? actionableCount(data) : 0;
    const badge = count > 0 ? `<span class="badge">${count}</span>` : "";
    return `<button type="button" class="bs-nav-item" data-nav="${item.key}" ${active ? 'aria-current="page"' : ""}><span>${item.label}</span>${badge}</button>`;
  }).join("");

  return `
    <aside class="bs-rail">
      <div class="bs-machine">
        <div class="name">${escapeHtml(machine.name)}</div>
        <div class="os">${escapeHtml(machine.os)}</div>
        <div class="health"><span class="dot" style="background:${health.color};box-shadow:0 0 0 3px ${health.tone}"></span>Last check: ${escapeHtml(health.text)}</div>
      </div>
      <div class="bs-rule"></div>
      <nav class="bs-nav">${nav}</nav>
      <div class="bs-rail-foot">
        <span class="left">100% local scan</span>
        <span class="ver">v3.0</span>
      </div>
    </aside>`;
}

function renderHeader() {
  const h = headerFor(state.error ? "error" : state.screen);
  return `
    <div class="bs-header">
      <h1>${escapeHtml(h.title)}</h1>
      <p>${escapeHtml(h.subtitle)}</p>
    </div>`;
}

function headerFor(screen) {
  const date = state.results ? formatDate(state.results.generated_at) : "";
  const map = {
    home: { title: "Home", subtitle: "Run a local scan and see what gets checked." },
    scanning: { title: "Scanning", subtitle: "Reading the system state. Nothing leaves this device." },
    overview: { title: "Overview", subtitle: "Last check · " + date },
    categories: { title: "Categories", subtitle: "Score per security area, points lost out of the maximum." },
    fixes: { title: "Issues", subtitle: "Findings ranked by severity, with the steps to fix them." },
    report: { title: "Report", subtitle: "Export a local report, on this machine only." },
    error: { title: "Scan stopped", subtitle: "The local scanner could not finish." }
  };
  return map[screen] || map.home;
}

function renderScreen() {
  if (state.error) return renderError();
  switch (state.screen) {
    case "scanning": return renderScanning();
    case "overview": return renderOverview();
    case "categories": return renderCategories();
    case "fixes": return renderFixes();
    case "report": return renderReport();
    default: return renderHome();
  }
}

/* ---------- Home ---------- */
function renderHome() {
  const last = state.results ? formatDate(state.results.generated_at) : "never this session";
  const controls = CONTROLS.map((c, i) => `
    <div class="bs-control">
      <span class="idx">${pad(i + 1)}</span>
      <div class="name">${escapeHtml(c.name)}</div>
      <div class="desc">${escapeHtml(c.desc)}</div>
      <div class="plat">${escapeHtml(c.platform)}</div>
    </div>`).join("");

  return `
    <div class="bs-view">
      <div class="bs-card pad bs-mb">
        <div class="bs-hero">
          <div class="copy">
            <h2>Check this device's security</h2>
            <p>BeSecured reads the local configuration (firewall, updates, accounts, encryption), then tells you what is fine, what is not, and how to fix each point.</p>
          </div>
          <div class="act">
            <button type="button" class="bs-cta" data-action="start"><span>Run the scan</span></button>
            <span class="last">Last: ${escapeHtml(last)}</span>
          </div>
        </div>
        <div class="bs-reassure">
          <span>Read only, no changes</span>
          <span>10 to 20 seconds</span>
          <span>Nothing is sent</span>
        </div>
      </div>

      <div class="bs-section-head">
        <span class="t">What gets checked</span>
        <span class="rule"></span>
        <span class="n">${CONTROLS.length} checks</span>
      </div>
      <div class="bs-card flat clip">${controls}</div>
    </div>`;
}

/* ---------- Scanning ---------- */
function renderScanning() {
  const rows = CONTROLS.map((c, i) => {
    const done = i < state.checksDone;
    return `
      <div class="row ${done ? "done" : ""}">
        <span class="mark">${done ? "✓" : ""}</span>
        <span class="nm">${escapeHtml(c.name)}</span>
      </div>`;
  }).join("");

  return `
    <div class="bs-view">
      <div class="bs-card bs-scan">
        <div class="h"><span class="pulse"></span><span class="t">Scanning this device…</span></div>
        <div class="bs-progress"><div class="bar" data-keepmotion></div></div>
        <p class="count" id="bs-scan-count">${state.checksDone} of ${CONTROLS.length} checks · nothing leaves this device</p>
        <div class="log">${rows}</div>
      </div>
    </div>`;
}

function updateScanProgress() {
  const count = document.getElementById("bs-scan-count");
  if (count) count.textContent = `${state.checksDone} of ${CONTROLS.length} checks · nothing leaves this device`;
  const rows = app.querySelectorAll(".bs-scan .row");
  rows.forEach((row, i) => {
    const done = i < state.checksDone;
    row.classList.toggle("done", done);
    const mark = row.querySelector(".mark");
    if (mark) mark.textContent = done ? "✓" : "";
  });
}

/* ---------- Overview ---------- */
function renderOverview() {
  const data = state.results;
  const tone = railHealth(data);
  const dist = distribution(data);
  const distbar = dist.filter((d) => d.value > 0)
    .map((d) => `<span style="flex:${d.value} 1 0;background:${d.fg}"></span>`).join("");
  const distCells = dist.map((d) => `
    <div class="item">
      <span class="swatch" style="background:${d.fg}"></span>
      <span class="v">${d.value}</span><span class="l">${d.dist}</span>
    </div>`).join("");

  const prio = priorityFindings(data);
  const prioRows = prio.length
    ? prio.map((f) => `
        <button type="button" class="bs-prio" data-nav="fixes">
          ${sevBadge(f.status)}
          <span class="title">${escapeHtml(f.name)}</span>
          <span class="cat">${escapeHtml(f.category)}</span>
        </button>`).join("")
    : `<div class="bs-empty">No critical or warning items.</div>`;

  return `
    <div class="bs-view">
      <div class="bs-card bs-score-block">
        <div class="bs-score-head">
          <div class="bs-score-tile"><span class="num">${data.overall_score}</span><span class="out">/100</span></div>
          <div class="bs-score-side">
            <span class="bs-grade"><span class="dot" style="background:${tone.color};box-shadow:0 0 0 3px ${tone.tone}"></span>Grade ${escapeHtml(data.grade || "—")}</span>
            <span class="bs-summary">${escapeHtml(summaryText(data))}</span>
          </div>
        </div>
        <div class="bs-distbar">${distbar}</div>
        <div class="bs-dist">${distCells}</div>
      </div>

      <div class="bs-card flat clip">
        <div class="bs-list-head">
          <span class="t">Top priority</span>
          <button type="button" class="bs-link" data-nav="fixes">See all →</button>
        </div>
        ${prioRows}
      </div>
    </div>`;
}

/* ---------- Categories ---------- */
function renderCategories() {
  const data = state.results;
  const rows = categoryRows(data).map((c) => {
    const m = SEV[c.status];
    const fill = c.notScored ? "" : `<div class="bs-score-fill" style="width:${c.pct}%;background:${m.fg}"></div>`;
    return `
      <div class="bs-cat-row">
        <div class="bs-col-domain">
          <span class="dot" style="background:${m.fg}"></span>
          <span class="name">${escapeHtml(c.category)}</span>
        </div>
        <div class="bs-col-note"><span class="note">${escapeHtml(c.note)}</span></div>
        <div class="bs-col-score">
          <div class="bs-score-cell">
            <div class="bs-score-track">${fill}</div>
            <span class="bs-score-text">${escapeHtml(c.scoreText)}</span>
          </div>
        </div>
        <div class="bs-col-state"><div class="bs-state-cell">${sevBadge(c.status)}</div></div>
      </div>`;
  }).join("");

  return `
    <div class="bs-view">
      <div class="bs-card flat clip">
        <div class="bs-cat-head">
          <div class="bs-col-domain">Area</div>
          <div class="bs-col-note">Finding</div>
          <div class="bs-col-score">Score</div>
          <div class="bs-col-state" style="text-align:right">State</div>
        </div>
        ${rows}
      </div>
      <p class="bs-note">An area with no applicable check on this machine is marked Skipped and does not count toward the score.</p>
    </div>`;
}

/* ---------- Issues ---------- */
function renderFixes() {
  const data = state.results;
  const cards = data.findings
    .filter((f) => f.status === "CRIT" || f.status === "WARN" || f.status === "INFO")
    .map(renderFindingCard).join("");

  const notes = data.findings
    .filter((f) => f.status === "OK" || f.status === "SKIP")
    .map((f) => `<div class="note">${escapeHtml(noteLine(f))}</div>`).join("");

  const noaction = notes
    ? `<div class="bs-card flat clip bs-noaction">
         <div class="head">No action needed</div>
         <div class="body">${notes}</div>
       </div>`
    : "";

  const empty = !cards
    ? `<div class="bs-card flat clip"><div class="bs-empty">Nothing to fix in this scan.</div></div>`
    : "";

  return `<div class="bs-view">${cards}${empty}${noaction}</div>`;
}

function renderFindingCard(f) {
  const showSteps = (f.status === "CRIT" || f.status === "WARN") && f.fix_steps && f.fix_steps.length;
  const steps = showSteps
    ? `<div>
         <div class="label">How to fix</div>
         <div class="bs-steps">${f.fix_steps.map((s, i) => `
           <div class="bs-step"><span class="num">${i + 1}</span><span class="txt">${escapeHtml(s)}</span></div>`).join("")}</div>
       </div>`
    : "";
  return `
    <div class="bs-card bs-find">
      <div class="bs-find-head">
        <div class="lhs">${sevBadge(f.status)}<span class="title">${escapeHtml(f.name)}</span></div>
        <div class="meta">${escapeHtml(f.category)} · ${escapeHtml(impactLabel(f.status))}</div>
      </div>
      <div class="bs-find-body">
        <div><div class="label">Finding</div><p>${escapeHtml(f.what_we_found)}</p></div>
        <div><div class="label">Why it matters</div><p>${escapeHtml(f.why_it_matters)}</p></div>
        ${steps}
      </div>
    </div>`;
}

/* ---------- Report ---------- */
function renderReport() {
  const data = state.results;
  const formats = [
    { id: "html", name: "HTML report", desc: "Readable in a browser, to keep or print." },
    { id: "json", name: "JSON data", desc: "Structured format for archiving or technical review." }
  ].map((r) => `
    <button type="button" class="bs-fmt-opt" data-format="${r.id}" aria-pressed="${state.reportFormat === r.id}">
      <span class="bs-radio"></span>
      <span><span class="nm">${escapeHtml(r.name)}</span><span class="ds">${escapeHtml(r.desc)}</span></span>
    </button>`).join("");

  const dist = distribution(data).filter((d) => d.value > 0)
    .map((d) => `<span style="flex:${d.value} 1 0;background:${d.fg}"></span>`).join("");

  return `
    <div class="bs-view">
      <div class="bs-report">
        <div class="left">
          <div class="bs-card pad">
            <h3>Report format</h3>
            <p class="sub">The report includes the score, the findings and the fix steps.</p>
            <div class="bs-fmt">${formats}</div>
          </div>

          <div class="bs-card pad">
            <div class="bs-dest-label">Destination</div>
            <div class="bs-dest-path">${escapeHtml(reportDir())}</div>
            <div class="bs-dest-note">
              <span class="dot"></span>
              <p>BeSecured only writes locally. If you point it at a synced folder (iCloud, Drive…), it refuses to write rather than let the report leak.</p>
            </div>
          </div>

          <div class="bs-export-row">
            <button type="button" class="bs-cta" data-action="export"><span>Export the report</span></button>
            ${state.exported ? `<span class="bs-exported"><span class="chk">✓</span>Saved to the local folder</span>` : ""}
          </div>
        </div>

        <div class="bs-doc-wrap">
          <div class="bs-doc-label">Document preview</div>
          <div class="bs-doc">
            <div class="brand">BeSecured</div>
            <div class="date">${escapeHtml(formatDate(data.generated_at))}</div>
            <div class="score"><span class="n">${data.overall_score}</span><span class="o">/100 · ${escapeHtml(data.grade || "—")}</span></div>
            <div class="thumb">${dist || '<span style="flex:1 1 0;background:#e8eaed"></span>'}</div>
            <div class="lines"><span style="width:100%"></span><span style="width:84%"></span><span style="width:92%"></span><span style="width:70%"></span></div>
          </div>
        </div>
      </div>
    </div>`;
}

/* ---------- Error ---------- */
function renderError() {
  return `
    <div class="bs-view">
      <div class="bs-card bs-error">
        <h2>The scan could not finish</h2>
        <p>${escapeHtml(state.error)}</p>
        <button type="button" class="bs-cta" data-action="start"><span>Retry</span></button>
      </div>
    </div>`;
}

/* ---------- Shared bits ---------- */
function sevBadge(status) {
  const m = SEV[status] || SEV.INFO;
  return `<span class="bs-sev ${m.cls}"><span class="g">${m.glyph}</span>${m.label}</span>`;
}

function impactLabel(status) {
  if (status === "CRIT") return "-5 pts";
  if (status === "WARN") return "-2 pts";
  return "no effect";
}

function noteLine(f) {
  return f.what_we_found || f.name;
}

function distribution(data) {
  return DIST_ORDER.map((status) => {
    const m = SEV[status];
    return { status, value: statusCount(data, status), fg: m.fg, dist: m.dist };
  });
}

function priorityFindings(data) {
  return data.findings.filter((f) => f.status === "CRIT" || f.status === "WARN");
}

function categoryRows(data) {
  const details = (data.score_details && data.score_details.category_details) || {};
  return Object.keys(data.category_scores || {})
    .sort((a, b) => a.localeCompare(b))
    .map((category) => {
      const raw = data.category_scores[category];
      const notScored = raw === null || raw === undefined;
      const detail = details[category] || {};
      const lost = Number(detail.lost_points ?? 0);
      const max = Number(detail.max_points ?? 0);
      const inCat = data.findings.filter((f) => f.category === category);
      let status = "OK";
      if (notScored) status = "SKIP";
      else if (inCat.some((f) => f.status === "CRIT")) status = "CRIT";
      else if (inCat.some((f) => f.status === "WARN")) status = "WARN";
      const issues = inCat.filter((f) => f.status === "CRIT" || f.status === "WARN").length;
      let note;
      if (notScored) note = "Not assessed on this system";
      else if (issues > 0) note = `${issues} issue${issues > 1 ? "s" : ""} to review out of ${inCat.length} check${inCat.length > 1 ? "s" : ""}`;
      else note = `${inCat.length} check${inCat.length > 1 ? "s" : ""}, all clear`;
      return {
        category, notScored, status, note,
        pct: notScored ? 0 : clampScore(raw),
        scoreText: notScored ? "—" : `${max - lost}/${max}`
      };
    });
}

function summaryText(data) {
  const crit = statusCount(data, "CRIT");
  const warn = statusCount(data, "WARN");
  if (crit > 0) {
    const head = `${cap(numWord(crit))} critical risk${crit > 1 ? "s" : ""} to handle first`;
    return warn > 0 ? `${head}, ${numWord(warn)} warning${warn > 1 ? "s" : ""}.` : `${head}.`;
  }
  if (warn > 0) {
    return `${cap(numWord(warn))} warning${warn > 1 ? "s" : ""} to fix, no critical risk.`;
  }
  return "Nothing to fix, the setup looks clean.";
}

function railHealth(data) {
  if (!data) return { text: "not run", color: "#9aa2af", tone: "rgba(154,162,175,0.18)" };
  if (statusCount(data, "CRIT") > 0) return { text: "needs attention", color: SEV.CRIT.fg, tone: SEV.CRIT.tone };
  if (statusCount(data, "WARN") > 0 || data.overall_score < 75) return { text: "review advised", color: SEV.WARN.fg, tone: SEV.WARN.tone };
  return { text: "healthy", color: SEV.OK.fg, tone: SEV.OK.tone };
}

/* ---------- Events ---------- */
function bindEvents() {
  app.querySelectorAll("[data-action='start']").forEach((b) => b.addEventListener("click", startScan));
  app.querySelectorAll("[data-action='export']").forEach((b) => b.addEventListener("click", exportReport));
  app.querySelectorAll("[data-format]").forEach((b) => b.addEventListener("click", () => {
    state.reportFormat = b.dataset.format;
    state.exported = false;
    render();
  }));
  app.querySelectorAll("[data-nav]").forEach((b) => b.addEventListener("click", () => navTo(b.dataset.nav)));
}

function navTo(key) {
  if (key === "home") { state.screen = "home"; state.error = ""; render(); return; }
  if (!state.results) { state.pending = key; startScan(); return; }
  state.screen = key;
  state.error = "";
  render();
}

/* ---------- Scan flow ---------- */
async function startScan() {
  if (scanTimer) clearInterval(scanTimer);
  state.error = "";
  state.results = null;
  state.exported = false;
  state.checksDone = 0;
  state.screen = "scanning";
  render();

  const started = performance.now();
  scanTimer = window.setInterval(() => {
    state.checksDone = Math.min(state.checksDone + 1, CONTROLS.length);
    updateScanProgress();
    if (state.checksDone >= CONTROLS.length) { clearInterval(scanTimer); scanTimer = null; }
  }, 220);

  let rawData = null;
  let scanError = null;
  try {
    rawData = await runLocalScan();
  } catch (error) {
    scanError = error;
  }

  const minVisible = 1900;
  const elapsed = performance.now() - started;
  if (elapsed < minVisible) await wait(minVisible - elapsed);
  if (scanTimer) { clearInterval(scanTimer); scanTimer = null; }
  state.checksDone = CONTROLS.length;

  if (scanError || rawData === null) {
    state.error = scanError && scanError.message ? scanError.message : "The local scanner did not respond.";
    state.pending = null;
    render();
    return;
  }

  try {
    state.results = normalizeScan(rawData);
  } catch (error) {
    state.error = error.message || "The scanner response does not match the BeSecured contract.";
    state.pending = null;
    render();
    return;
  }

  state.screen = state.pending || "overview";
  state.pending = null;
  render();
}

async function runLocalScan() {
  const response = await fetch("/api/scan", {
    method: "POST",
    headers: { Accept: "application/json" },
    cache: "no-store"
  });
  if (!response.ok) {
    let detail = "";
    try {
      const payload = await response.json();
      detail = payload.detail || payload.error || "";
    } catch {
      detail = "";
    }
    throw new Error(detail || "Start the interface with python -m besecured.ui to launch the local scanner.");
  }
  return response.json();
}

function normalizeScan(data) {
  const required = ["schema_version", "scan_source", "generated_at", "system_info", "status_counts", "category_scores", "overall_score", "grade", "score_details", "scoring_note", "findings"];
  const missing = required.filter((key) => data[key] === undefined);
  if (missing.length) {
    throw new Error(`Incomplete response, missing keys: ${missing.join(", ")}`);
  }
  const findings = Array.isArray(data.findings) ? data.findings.map(normalizeFinding) : [];
  return {
    schema_version: data.schema_version,
    scan_source: data.scan_source,
    generated_at: data.generated_at,
    system_info: data.system_info || {},
    status_counts: normalizeStatusCounts(data.status_counts, findings),
    category_scores: data.category_scores || {},
    overall_score: clampScore(data.overall_score),
    grade: data.grade || "",
    score_details: data.score_details || {},
    scoring_note: data.scoring_note || "",
    findings: sortFindings(findings)
  };
}

function normalizeFinding(finding, index) {
  const status = String(finding.status || "INFO").toUpperCase();
  const safeStatus = STATUS_ORDER[status] === undefined ? "INFO" : status;
  const what = finding.what_we_found || finding.detail || "No detail available.";
  const why = finding.why_it_matters || finding.explanation || "This item may affect the local posture.";
  const how = finding.how_to_fix || finding.recommended_action || finding.remediation || "Review if needed.";
  const supportedOs = Array.isArray(finding.supported_os) ? finding.supported_os.filter(Boolean) : ["Windows", "macOS", "Linux"];
  return {
    id: finding.id || `f-${index}`,
    category: finding.category || "System",
    name: finding.name || `Check ${index + 1}`,
    status: safeStatus,
    what_we_found: what,
    why_it_matters: why,
    how_to_fix: how,
    fix_steps: Array.isArray(finding.fix_steps) && finding.fix_steps.length ? finding.fix_steps : [how],
    supported_os: supportedOs,
    requires_admin: Boolean(finding.requires_admin)
  };
}

function normalizeStatusCounts(counts, findings) {
  const out = {};
  DIST_ORDER.forEach((s) => {
    out[s] = Number((counts || {})[s] ?? countStatus(findings, s));
  });
  return out;
}

function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const rank = (STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9);
    if (rank !== 0) return rank;
    return a.name.localeCompare(b.name);
  });
}

/* ---------- Export ---------- */
function exportReport() {
  const data = state.results;
  let blob;
  let filename;
  if (state.reportFormat === "json") {
    blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    filename = `BeSecured-report-${dateSlug(data)}.json`;
  } else {
    blob = new Blob([renderExportHtml(data)], { type: "text/html" });
    filename = `BeSecured-report-${dateSlug(data)}.html`;
  }
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  state.exported = true;
  render();
}

function renderExportHtml(data) {
  const findings = data.findings.map((f) => `
    <section>
      <h2>${escapeHtml(f.name)}</h2>
      <p><strong>Status</strong> ${escapeHtml(SEV[f.status] ? SEV[f.status].label : f.status)}</p>
      <p><strong>Category</strong> ${escapeHtml(f.category)}</p>
      <p><strong>Systems</strong> ${escapeHtml(osLabel(f.supported_os))}</p>
      <p><strong>Rights</strong> ${f.requires_admin ? "admin" : "user"}</p>
      <p><strong>Finding</strong> ${escapeHtml(f.what_we_found)}</p>
      <p><strong>Why it matters</strong> ${escapeHtml(f.why_it_matters)}</p>
      <p><strong>How to fix</strong></p>
      <ol>${f.fix_steps.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ol>
    </section>`).join("");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>BeSecured, local report</title>
  <style>
    body { margin: 0; padding: 32px; background: #eef1f6; color: #15181d; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; line-height: 1.55; }
    main { max-width: 820px; margin: 0 auto; background: #fff; padding: 28px; border-radius: 14px; border: 1px solid #e4e7eb; }
    h1 { margin: 0 0 12px; font-size: 22px; }
    h2 { margin: 0 0 6px; font-size: 16px; }
    section { padding: 16px 0; border-top: 1px solid #e4e7eb; }
    section:first-of-type { border-top: 0; }
    p, ol { margin: 4px 0; font-size: 13px; }
  </style>
</head>
<body>
  <main>
    <h1>BeSecured, local report</h1>
    <p>Scan date ${escapeHtml(formatDate(data.generated_at))}</p>
    <p>System ${escapeHtml(systemLabel(data))}</p>
    <p>Score ${data.overall_score} out of 100, grade ${escapeHtml(data.grade || "")}</p>
    <p>${escapeHtml(summaryText(data))}</p>
    ${findings}
  </main>
</body>
</html>`;
}

/* ---------- Helpers ---------- */
function readMachine(data) {
  const sys = (data && data.system_info) || {};
  const name = sys.Hostname || sys.hostname || "This device";
  const sysName = { Darwin: "macOS", Windows: "Windows", Linux: "Linux" }[sys.System] || sys.System || "System";
  const rel = sys.Release ? " " + sys.Release : "";
  const arch = sys.Arch ? " · " + sys.Arch : "";
  const os = data ? (sysName + rel + arch).trim() : "waiting for the scan";
  return { name, os };
}

function systemLabel(data) {
  const sys = (data && data.system_info) || {};
  return sys.OS || sys.System || "Unknown OS";
}

function reportDir() {
  const sys = (state.results && state.results.system_info) || {};
  if (sys.System === "Windows") return "%LOCALAPPDATA%\\BeSecured\\Reports\\";
  if (sys.System === "Darwin") return "~/Library/Application Support/BeSecured/Reports/";
  return "~/.local/state/besecured/reports/";
}

function osLabel(supportedOs) {
  if (!Array.isArray(supportedOs) || supportedOs.length === 0) return "not specified";
  return supportedOs.join(", ");
}

function actionableCount(data) {
  return statusCount(data, "CRIT") + statusCount(data, "WARN");
}

function statusCount(data, status) {
  return Number((data.status_counts || {})[status] ?? 0);
}

function countStatus(findings, status) {
  return findings.filter((f) => f.status === status).length;
}

function clampScore(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return 0;
  return Math.max(0, Math.min(100, Math.round(number)));
}

function numWord(n) {
  return n >= 0 && n < NUM.length ? NUM[n] : String(n);
}

function cap(text) {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function dateSlug(data) {
  return String(data.generated_at).slice(0, 10);
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("en-GB", {
    year: "numeric", month: "long", day: "2-digit", hour: "2-digit", minute: "2-digit"
  }).format(date);
}

function pad(value) {
  return String(value).padStart(2, "0");
}

function wait(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

render();
