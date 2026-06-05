const scanCategories = ["Network", "System", "Accounts", "Protection", "Updates"];
const severityOrder = { critical: 0, warning: 1, info: 2, passed: 3, skipped: 4 };
const statusColors = {
  critical: "#c83333",
  warning: "#b96a00",
  passed: "#18834f",
  info: "#2f6fb7",
  skipped: "#728093"
};

const state = {
  screen: "start",
  issueFilter: "all",
  progressIndex: 0,
  progressPercent: 0,
  results: null,
  error: "",
  exported: false
};

const app = document.getElementById("app");

function icon(name) {
  const paths = {
    shield: '<path d="M12 3l7 3v5c0 4.2-2.8 7.4-7 9-4.2-1.6-7-4.8-7-9V6l7-3z"></path><path d="M9.5 12l1.7 1.7 3.8-4"></path>',
    play: '<path d="M8 5v14l11-7L8 5z"></path>',
    check: '<path d="M20 6L9 17l-5-5"></path>',
    lock: '<rect x="5" y="10" width="14" height="10" rx="2"></rect><path d="M8 10V8a4 4 0 0 1 8 0v2"></path>',
    refresh: '<path d="M20 12a8 8 0 0 1-14.9 4"></path><path d="M4 16v5h5"></path><path d="M4 12A8 8 0 0 1 18.9 8"></path><path d="M20 8V3h-5"></path>',
    file: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"></path><path d="M14 3v5h5"></path><path d="M8 13h8"></path><path d="M8 17h5"></path>',
    alert: '<path d="M12 9v4"></path><path d="M12 17h.01"></path><path d="M10.3 4.4 2.8 17.2A2 2 0 0 0 4.5 20h15a2 2 0 0 0 1.7-2.8L13.7 4.4a2 2 0 0 0-3.4 0z"></path>',
    arrow: '<path d="M5 12h14"></path><path d="M13 6l6 6-6 6"></path>'
  };
  return `<svg aria-hidden="true" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${paths[name] || paths.shield}</svg>`;
}

function render() {
  app.innerHTML = `
    <div class="product-shell">
      ${renderTopbar()}
      ${renderTabs()}
      <main class="main-area">
        ${renderScreen()}
      </main>
    </div>
  `;
  bindEvents();
}

function renderTopbar() {
  const hasResults = Boolean(state.results);
  return `
    <header class="topbar">
      <div class="brand">
        <span class="brand-mark">${icon("shield")}</span>
        <span>
          <span class="brand-title">BeSecured</span>
          <span class="brand-subtitle">Local cybersecurity risk scanner</span>
        </span>
      </div>
      <div class="top-actions">
        ${hasResults ? '<button class="ghost-button" data-action="start-scan"><span class="button-icon">' + icon("refresh") + '</span>Run again</button>' : ""}
      </div>
    </header>
  `;
}

function renderTabs() {
  if (!state.results) {
    return "";
  }
  const tabs = [
    ["results", "Results"],
    ["issues", "Issues"],
    ["report", "Report"]
  ];
  return `
    <nav class="view-tabs" aria-label="Scan views">
      ${tabs.map(([screen, label]) => `<button class="tab-button" data-screen="${screen}" aria-selected="${state.screen === screen}">${label}</button>`).join("")}
    </nav>
  `;
}

function renderScreen() {
  if (state.error) {
    return renderError();
  }
  if (state.screen === "progress") {
    return renderProgress();
  }
  if (state.screen === "results" && state.results) {
    return renderResults();
  }
  if (state.screen === "issues" && state.results) {
    return renderIssues();
  }
  if (state.screen === "report" && state.results) {
    return renderReport();
  }
  return renderStart();
}

function renderStart() {
  return `
    <section class="utility-grid" aria-labelledby="start-title">
      <div class="status-panel">
        <div class="status-head">
          <span class="status-dot is-ready"></span>
          <div class="status-copy">
            <span class="screen-label">Device status</span>
            <h1 id="start-title">Ready to check</h1>
            <p>No scan has been run in this UI session.</p>
          </div>
        </div>
        <div class="status-metrics" aria-label="Current scanner state">
          <div><span>Last scan</span><strong>Not run</strong></div>
          <div><span>Data source</span><strong>scan-results.json</strong></div>
          <div><span>Scope</span><strong>UI preview only</strong></div>
        </div>
        <div class="status-actions">
          <button class="primary-button" data-action="start-scan"><span class="button-icon">${icon("play")}</span>Start scan</button>
          <span class="demo-note">${icon("alert")} Prototype: loads local sample results only.</span>
        </div>
      </div>

      <div class="module-stack" aria-label="Scanner modules">
        <article class="module-card">
          <div class="module-header">
            <span class="module-icon">${icon("shield")}</span>
            <div>
              <h2>Scanner</h2>
              <p>Network, system, accounts, protection and updates.</p>
            </div>
          </div>
          <button class="secondary-button" data-action="start-scan"><span class="button-icon">${icon("play")}</span>Run preview</button>
        </article>
        <article class="module-card">
          <div class="module-header">
            <span class="module-icon">${icon("lock")}</span>
            <div>
              <h2>Privacy</h2>
              <p>Local report flow, no account, no upload, no cloud service.</p>
            </div>
          </div>
          <ul class="compact-list">
            <li>${icon("check")}<span>Data stays on this device</span></li>
            <li>${icon("check")}<span>Scanner bridge not wired yet</span></li>
          </ul>
        </article>
        <article class="module-card">
          <div class="module-header">
            <span class="module-icon">${icon("file")}</span>
            <div>
              <h2>Report</h2>
              <p>After a scan, export a self contained HTML summary.</p>
            </div>
          </div>
        </article>
      </div>
    </section>
  `;
}

function renderProgress() {
  const current = scanCategories[Math.min(state.progressIndex, scanCategories.length - 1)];
  return `
    <section class="progress-panel" aria-labelledby="progress-title">
      <div class="progress-header">
        <div>
          <h1 id="progress-title">Loading local scan preview</h1>
          <p>Current step: ${escapeHtml(current)}</p>
          <div class="demo-note">${icon("alert")} Prototype mode: this progress view is simulated and reads <strong>scan-results.json</strong>.</div>
        </div>
        <div class="progress-percent">${state.progressPercent}%</div>
      </div>
      <div class="progress-track" aria-label="Scan progress">
        <div class="progress-fill" style="width:${state.progressPercent}%"></div>
      </div>
      <div class="category-list">
        ${scanCategories.map((category, index) => renderProgressStep(category, index)).join("")}
      </div>
    </section>
  `;
}

function renderProgressStep(category, index) {
  const isDone = index < state.progressIndex;
  const isActive = index === state.progressIndex;
  const className = isDone ? "is-done" : isActive ? "is-active" : "";
  const label = isDone ? "Complete" : isActive ? "In progress" : "Waiting";
  const detail = isDone ? "Sample result loaded" : isActive ? "Preparing category data" : "Queued";
  return `
    <div class="category-step ${className}">
      <span class="step-icon">${isDone ? icon("check") : icon("shield")}</span>
      <span>
        <span class="step-title">${escapeHtml(category)}</span>
        <span class="step-detail">${detail}</span>
      </span>
      <span class="step-state">${label}</span>
    </div>
  `;
}

function renderResults() {
  const data = state.results;
  const scoreColor = colorForScore(data.score);
  return `
    <section class="results-grid" aria-labelledby="results-title">
      <div class="result-panel">
        <div class="result-status" style="--score-color:${scoreColor}">
          <div class="score-tile">
            <strong>${data.score}</strong>
            <span>Risk score</span>
          </div>
          <div class="results-heading">
            <h1 id="results-title">${statusText(data)}</h1>
            <p>${riskDescription(data)}</p>
            ${mockNotice(data)}
          </div>
        </div>
        <div class="summary-strip" aria-label="Summary counts">
          <div class="summary-item is-critical"><strong>${data.summary.critical}</strong><span>Critical</span></div>
          <div class="summary-item is-warning"><strong>${data.summary.warning}</strong><span>Warning</span></div>
          <div class="summary-item is-passed"><strong>${data.summary.passed}</strong><span>Passed</span></div>
        </div>
      </div>
      <aside class="side-panel" aria-label="Category summary">
        <h2>Category view</h2>
        <div class="category-bars">
          ${renderCategoryBars(data)}
        </div>
        <div class="button-row" style="margin-top:22px">
          <button class="secondary-button" data-screen="issues"><span class="button-icon">${icon("alert")}</span>View issues</button>
          <button class="secondary-button" data-screen="report"><span class="button-icon">${icon("file")}</span>Report</button>
        </div>
      </aside>
    </section>
  `;
}

function renderCategoryBars(data) {
  const categories = scanCategories.map((category) => {
    const categoryFindings = data.findings.filter((finding) => finding.category === category);
    const bad = categoryFindings.filter((finding) => finding.severity === "critical" || finding.severity === "warning").length;
    const total = Math.max(categoryFindings.length, 1);
    const goodPercent = Math.round(((total - bad) / total) * 100);
    return { category, bad, total, goodPercent };
  });
  return categories.map((item) => `
    <div class="category-bar">
      <div class="bar-head">
        <strong>${escapeHtml(item.category)}</strong>
        <span>${item.bad} to review</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill" style="width:${item.goodPercent}%"></div>
      </div>
    </div>
  `).join("");
}

function renderIssues() {
  const filtered = sortedFindings(state.results.findings).filter((finding) => {
    if (state.issueFilter === "all") {
      return true;
    }
    return finding.severity === state.issueFilter;
  });
  return `
    <section aria-labelledby="issues-title">
      <div class="issues-heading">
        <h1 id="issues-title">Issues by severity</h1>
        <p>Critical and Warning items appear first, then Info and passed checks.</p>
      </div>
      <div class="issue-toolbar" aria-label="Issue filters">
        ${renderFilter("all", "All")}
        ${renderFilter("critical", "Critical")}
        ${renderFilter("warning", "Warning")}
        ${renderFilter("info", "Info")}
        ${renderFilter("passed", "Passed")}
        ${renderFilter("skipped", "Skipped")}
      </div>
      <div class="issue-list">
        ${filtered.length ? filtered.map(renderIssueCard).join("") : renderEmptyIssues()}
      </div>
    </section>
  `;
}

function renderFilter(value, label) {
  return `<button class="filter-button" data-filter="${value}" aria-pressed="${state.issueFilter === value}">${label}</button>`;
}

function renderIssueCard(finding) {
  const color = statusColors[finding.severity] || statusColors.info;
  return `
    <article class="issue-card" style="--status-color:${color}">
      <div class="issue-card-head">
        <div>
          <h2 class="issue-title">${escapeHtml(finding.title)}</h2>
          <div class="issue-meta">
            <span class="pill status-pill">${severityLabel(finding.severity)}</span>
            <span class="pill">${escapeHtml(finding.category)}</span>
            ${finding.requires_admin ? '<span class="pill">Needs admin</span>' : ""}
            ${finding.supported ? "" : '<span class="pill">Unsupported</span>'}
          </div>
        </div>
      </div>
      <div class="issue-sections">
        <section class="issue-section">
          <h3>What we found</h3>
          <p>${escapeHtml(finding.detail)}</p>
        </section>
        <section class="issue-section">
          <h3>Why it matters</h3>
          <p>${escapeHtml(finding.why_it_matters)}</p>
        </section>
        <section class="issue-section">
          <h3>How to fix it</h3>
          <ul class="fix-list">
            ${finding.fix_steps.map((step) => `<li>${icon("check")}<span>${escapeHtml(step)}</span></li>`).join("")}
          </ul>
        </section>
      </div>
    </article>
  `;
}

function renderEmptyIssues() {
  return `
    <div class="empty-panel">
      <h2>No findings in this filter</h2>
      <p>Choose another severity to see the rest of the local sample results.</p>
    </div>
  `;
}

function renderReport() {
  const data = state.results;
  const issueCount = data.summary.critical + data.summary.warning;
  return `
    <section class="report-grid" aria-labelledby="report-title">
      <div class="report-panel">
        <div class="report-heading">
          <h1 id="report-title">Local report</h1>
          <p>Export a self contained HTML summary from the loaded scan data.</p>
        </div>
        <div class="report-details">
          ${reportRow("Scan date", formatDate(data.scan_time))}
          ${reportRow("Operating system", data.os_name)}
          ${reportRow("Risk score", `${data.score} / 100`)}
          ${reportRow("Issues to review", String(issueCount))}
          ${reportRow("Data source", data.data_source === "mock" ? "Local sample JSON" : "Scanner JSON")}
        </div>
        <div class="report-actions" style="margin-top:20px">
          <button class="primary-button" data-action="export-report"><span class="button-icon">${icon("file")}</span>Export report</button>
        </div>
        ${state.exported ? '<div class="export-note">' + icon("check") + " Export started in this browser.</div>" : ""}
      </div>
      <aside class="privacy-panel">
        <h2>Privacy</h2>
        <ul class="privacy-list">
          <li>${icon("check")}<span>Report is generated in the browser from local data.</span></li>
          <li>${icon("check")}<span>No server upload is performed.</span></li>
          <li>${icon("lock")}<span>Sample data can be replaced by scanner JSON later.</span></li>
        </ul>
      </aside>
    </section>
  `;
}

function reportRow(label, value) {
  return `<div class="report-row"><strong>${escapeHtml(label)}</strong><span>${escapeHtml(value)}</span></div>`;
}

function renderError() {
  return `
    <div class="empty-panel">
      <div class="error-box">${escapeHtml(state.error)}</div>
      <div class="button-row">
        <button class="secondary-button" data-action="reset">Back to start</button>
      </div>
    </div>
  `;
}

function bindEvents() {
  app.querySelectorAll("[data-action='start-scan']").forEach((button) => {
    button.addEventListener("click", startScan);
  });
  app.querySelectorAll("[data-action='reset']").forEach((button) => {
    button.addEventListener("click", resetApp);
  });
  app.querySelectorAll("[data-action='export-report']").forEach((button) => {
    button.addEventListener("click", exportReport);
  });
  app.querySelectorAll("[data-screen]").forEach((button) => {
    button.addEventListener("click", () => {
      state.screen = button.dataset.screen;
      render();
    });
  });
  app.querySelectorAll("[data-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      state.issueFilter = button.dataset.filter;
      render();
    });
  });
}

async function startScan() {
  state.error = "";
  state.results = null;
  state.exported = false;
  state.screen = "progress";
  state.progressIndex = 0;
  state.progressPercent = 4;
  render();

  let rawData;
  try {
    rawData = await loadScanResults();
  } catch (error) {
    state.error = "Could not load scan-results.json from the local UI folder.";
    state.screen = "start";
    render();
    return;
  }

  for (let index = 0; index < scanCategories.length; index += 1) {
    state.progressIndex = index;
    state.progressPercent = Math.round(((index + 0.25) / scanCategories.length) * 100);
    render();
    await wait(420);
    state.progressPercent = Math.round(((index + 1) / scanCategories.length) * 100);
    render();
    await wait(180);
  }

  state.results = normalizeScan(rawData);
  state.screen = "results";
  state.progressIndex = scanCategories.length;
  state.progressPercent = 100;
  render();
}

async function loadScanResults() {
  const response = await fetch("scan-results.json", { cache: "no-store" });
  if (!response.ok) {
    throw new Error("scan-results.json unavailable");
  }
  return response.json();
}

function normalizeScan(data) {
  const findings = Array.isArray(data.findings) ? data.findings.map(normalizeFinding) : [];
  const summary = normalizeSummary(data, findings);
  const score = clampScore(data.score ?? data.overall_score ?? 0);
  return {
    data_source: data.data_source || "scanner",
    scanner_note: data.scanner_note || "",
    os_name: data.os_name || data.system_info?.OS || "Unknown OS",
    scan_time: data.scan_time || data.generated_at || new Date().toISOString(),
    score,
    risk_level: data.risk_level || riskFromScore(score),
    summary,
    findings: sortedFindings(findings)
  };
}

function normalizeFinding(finding, index) {
  const status = String(finding.status || "").toUpperCase();
  const severity = finding.severity || severityFromStatus(status);
  const remediation = finding.remediation ? [finding.remediation] : [];
  return {
    id: finding.id || `finding-${index}`,
    category: finding.category || "System",
    title: finding.title || finding.name || "Security check",
    severity,
    status: status || statusFromSeverity(severity),
    detail: finding.detail || "No detail available.",
    why_it_matters: finding.why_it_matters || finding.remediation || "This item can affect the local security posture.",
    fix_steps: Array.isArray(finding.fix_steps) && finding.fix_steps.length ? finding.fix_steps : remediation.length ? remediation : ["No action needed."],
    supported: typeof finding.supported === "boolean" ? finding.supported : status !== "SKIP",
    requires_admin: Boolean(finding.requires_admin)
  };
}

function normalizeSummary(data, findings) {
  const fromData = data.summary || {};
  const statusCounts = data.status_counts || {};
  return {
    critical: Number(fromData.critical ?? statusCounts.CRIT ?? countSeverity(findings, "critical")),
    warning: Number(fromData.warning ?? statusCounts.WARN ?? countSeverity(findings, "warning")),
    passed: Number(fromData.passed ?? statusCounts.OK ?? countSeverity(findings, "passed")),
    info: Number(fromData.info ?? statusCounts.INFO ?? countSeverity(findings, "info")),
    skipped: Number(fromData.skipped ?? statusCounts.SKIP ?? countSeverity(findings, "skipped"))
  };
}

function sortedFindings(findings) {
  return [...findings].sort((a, b) => {
    const rank = (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9);
    if (rank !== 0) {
      return rank;
    }
    return a.title.localeCompare(b.title);
  });
}

function countSeverity(findings, severity) {
  return findings.filter((finding) => finding.severity === severity).length;
}

function severityFromStatus(status) {
  if (status === "CRIT") {
    return "critical";
  }
  if (status === "WARN") {
    return "warning";
  }
  if (status === "OK") {
    return "passed";
  }
  if (status === "SKIP") {
    return "skipped";
  }
  return "info";
}

function statusFromSeverity(severity) {
  return {
    critical: "CRIT",
    warning: "WARN",
    passed: "OK",
    skipped: "SKIP",
    info: "INFO"
  }[severity] || "INFO";
}

function severityLabel(severity) {
  return {
    critical: "Critical",
    warning: "Warning",
    passed: "OK",
    info: "Info",
    skipped: "Skipped"
  }[severity] || "Info";
}

function riskFromScore(score) {
  if (score >= 85) {
    return "good";
  }
  if (score >= 60) {
    return "warning";
  }
  return "high";
}

function statusText(data) {
  if (data.score >= 85 || data.risk_level === "good") {
    return "Your device looks good";
  }
  if (data.score >= 60 || data.risk_level === "warning") {
    return "Some issues need attention";
  }
  return "High risk, fix these first";
}

function riskDescription(data) {
  const issueCount = data.summary.critical + data.summary.warning;
  if (issueCount === 0) {
    return "Passed checks dominate this local sample report.";
  }
  return `${issueCount} issue${issueCount === 1 ? "" : "s"} should be reviewed before this device is considered clean.`;
}

function mockNotice(data) {
  if (data.data_source !== "mock") {
    return '<div class="local-note">' + icon("lock") + " Loaded from scanner JSON.</div>";
  }
  return '<div class="demo-note">' + icon("alert") + " Mock data: the UI has not executed real system checks.</div>";
}

function colorForScore(score) {
  if (score >= 85) {
    return statusColors.passed;
  }
  if (score >= 60) {
    return statusColors.warning;
  }
  return statusColors.critical;
}

function clampScore(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return 0;
  }
  return Math.max(0, Math.min(100, Math.round(number)));
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat("en", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

function exportReport() {
  const html = renderExportHtml(state.results);
  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `BeSecured-report-${state.results.scan_time.slice(0, 10)}.html`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  state.exported = true;
  render();
}

function renderExportHtml(data) {
  const issues = sortedFindings(data.findings).map((finding) => `
    <section>
      <h2>${escapeHtml(finding.title)}</h2>
      <p><strong>Status:</strong> ${escapeHtml(severityLabel(finding.severity))}</p>
      <p><strong>What we found:</strong> ${escapeHtml(finding.detail)}</p>
      <p><strong>Why it matters:</strong> ${escapeHtml(finding.why_it_matters)}</p>
      <p><strong>How to fix it:</strong></p>
      <ul>${finding.fix_steps.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ul>
    </section>
  `).join("");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>BeSecured Report</title>
  <style>
    body { margin: 0; padding: 32px; color: #142033; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.5; background: #f4f7fb; }
    main { max-width: 920px; margin: 0 auto; }
    header, section { margin-bottom: 16px; padding: 18px; background: #fff; border: 1px solid #d7e1ec; border-radius: 8px; }
    h1, h2 { margin: 0 0 10px; }
    p { margin: 7px 0; }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>BeSecured Report</h1>
      <p>Scan date: ${escapeHtml(formatDate(data.scan_time))}</p>
      <p>Operating system: ${escapeHtml(data.os_name)}</p>
      <p>Score: ${data.score} / 100</p>
      <p>Issues to review: ${data.summary.critical + data.summary.warning}</p>
    </header>
    ${issues}
  </main>
</body>
</html>`;
}

function resetApp() {
  state.screen = "start";
  state.error = "";
  state.results = null;
  state.exported = false;
  render();
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
