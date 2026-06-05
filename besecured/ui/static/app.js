const scanCategories = ["Network", "System", "Accounts", "Protection", "Updates"];
const statusOrder = { CRIT: 0, WARN: 1, INFO: 2, OK: 3, SKIP: 4 };
const statusColors = {
  CRIT: "#c83333",
  WARN: "#b96a00",
  OK: "#18834f",
  INFO: "#2f6fb7",
  SKIP: "#728093"
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
          <div><span>Data source</span><strong>Local scanner</strong></div>
          <div><span>Scope</span><strong>This device</strong></div>
        </div>
        <div class="status-actions">
          <button class="primary-button" data-action="start-scan"><span class="button-icon">${icon("play")}</span>Start scan</button>
          <span class="demo-note">${icon("alert")} Runs local checks only. No account, cloud service or upload.</span>
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
          <button class="secondary-button" data-action="start-scan"><span class="button-icon">${icon("play")}</span>Run scan</button>
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
            <li>${icon("check")}<span>The UI calls the local scanner engine</span></li>
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
          <h1 id="progress-title">Running local scan</h1>
          <p>Current step: ${escapeHtml(current)}</p>
          <div class="demo-note">${icon("alert")} The scanner is checking this machine through the local Python engine.</div>
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
  const detail = isDone ? "Checked" : isActive ? "Running local checks" : "Queued";
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
  const scoreColor = colorForScore(data.overall_score);
  return `
    <section class="results-grid" aria-labelledby="results-title">
      <div class="result-panel">
        <div class="result-status" style="--score-color:${scoreColor}">
          <div class="score-tile">
            <strong>${data.overall_score}</strong>
            <span>Risk score</span>
          </div>
          <div class="results-heading">
            <h1 id="results-title">${statusText(data)}</h1>
            <p>${riskDescription(data)}</p>
            ${sourceNotice(data)}
          </div>
        </div>
        <div class="summary-strip" aria-label="Summary counts">
          <div class="summary-item is-critical"><strong>${statusCount(data, "CRIT")}</strong><span>Critical</span></div>
          <div class="summary-item is-warning"><strong>${statusCount(data, "WARN")}</strong><span>Warning</span></div>
          <div class="summary-item is-info"><strong>${statusCount(data, "INFO")}</strong><span>Info</span></div>
          <div class="summary-item is-passed"><strong>${statusCount(data, "OK")}</strong><span>OK</span></div>
          <div class="summary-item is-skipped"><strong>${statusCount(data, "SKIP")}</strong><span>Skipped</span></div>
        </div>
        <div class="score-explain">
          <h2>Score calculation</h2>
          <p>${escapeHtml(scoreSummary(data))}</p>
          <div class="weight-row">
            ${renderWeight("CRIT", data)}
            ${renderWeight("WARN", data)}
            ${renderWeight("OK", data)}
          </div>
          <ul class="score-steps">
            ${scoreSteps(data).map((step) => `<li>${escapeHtml(step)}</li>`).join("")}
          </ul>
        </div>
      </div>
      <aside class="side-panel" aria-label="Category summary">
        <h2>Category impact</h2>
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
  const categoryNames = categoriesForResults(data);
  const categories = categoryNames.map((category) => {
    const categoryFindings = data.findings.filter((finding) => finding.category === category);
    const bad = categoryFindings.filter((finding) => finding.status === "CRIT" || finding.status === "WARN").length;
    const total = Math.max(categoryFindings.length, 1);
    const fallbackScore = Math.round(((total - bad) / total) * 100);
    const score = data.category_scores[category] ?? fallbackScore;
    const detail = data.score_details?.category_details?.[category] || {};
    return {
      category,
      bad,
      score,
      lostPoints: Number(detail.lost_points ?? 0),
      maxPoints: Number(detail.max_points ?? 0)
    };
  });
  return categories.map((item) => `
    <div class="category-bar">
      <div class="bar-head">
        <strong>${escapeHtml(item.category)}</strong>
        <span>${item.bad} to review, ${item.lostPoints}/${item.maxPoints} pts lost</span>
      </div>
      <div class="bar-track">
        <div class="bar-fill" style="width:${item.score}%"></div>
      </div>
    </div>
  `).join("");
}

function renderIssues() {
  const filtered = sortedFindings(state.results.findings).filter((finding) => {
    if (state.issueFilter === "all") {
      return true;
    }
    return finding.status === state.issueFilter;
  });
  return `
    <section aria-labelledby="issues-title">
      <div class="issues-heading">
        <h1 id="issues-title">Issues by severity</h1>
        <p>Critical and Warning items appear first, then Info and OK checks.</p>
      </div>
      <div class="issue-toolbar" aria-label="Issue filters">
        ${renderFilter("all", "All")}
        ${renderFilter("CRIT", "Critical")}
        ${renderFilter("WARN", "Warning")}
        ${renderFilter("INFO", "Info")}
        ${renderFilter("OK", "OK")}
        ${renderFilter("SKIP", "Skipped")}
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
  const color = statusColors[finding.status] || statusColors.INFO;
  return `
    <article class="issue-card" style="--status-color:${color}">
      <div class="issue-card-head">
        <div>
          <h2 class="issue-title">${escapeHtml(finding.name)}</h2>
          <div class="issue-meta">
            <span class="pill status-pill">${statusLabel(finding.status)}</span>
            <span class="pill">${escapeHtml(finding.category)}</span>
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
          <p>${escapeHtml(finding.explanation)}</p>
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
      <p>Choose another status to see the rest of the local scan results.</p>
    </div>
  `;
}

function renderReport() {
  const data = state.results;
  const issueCount = statusCount(data, "CRIT") + statusCount(data, "WARN");
  return `
    <section class="report-grid" aria-labelledby="report-title">
      <div class="report-panel">
        <div class="report-heading">
          <h1 id="report-title">Local report</h1>
          <p>Export a self contained HTML summary from the loaded scan data.</p>
        </div>
        <div class="report-details">
          ${reportRow("Scan date", formatDate(data.generated_at))}
          ${reportRow("Operating system", systemLabel(data))}
          ${reportRow("Risk score", `${data.overall_score} / 100`)}
          ${reportRow("Score formula", scoreFormula(data))}
          ${reportRow("Severity points", `${scoreLostPoints(data)} lost / ${scoreMaxPoints(data)} max`)}
          ${reportRow("Issues to review", String(issueCount))}
          ${reportRow("Data source", data.scan_source === "sample" ? "Prototype sample JSON" : "Local scanner")}
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
          <li>${icon("lock")}<span>The scan is started by the local Python server.</span></li>
        </ul>
      </aside>
    </section>
  `;
}

function reportRow(label, value) {
  return `<div class="report-row"><strong>${escapeHtml(label)}</strong><span>${escapeHtml(value)}</span></div>`;
}

function renderWeight(status, data) {
  const details = data.score_details || {};
  const weights = details.severity_weights || {};
  const impact = details.status_impact?.[status] || {};
  const weight = Number(weights[status] ?? 0);
  const lost = Number(impact.lost_points ?? 0);
  return `
    <div class="weight-pill">
      <strong>${statusLabel(status)}</strong>
      <span>${weight} pts each, ${lost} lost</span>
    </div>
  `;
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

  let rawData = null;
  let scanError = null;
  let scanDone = false;
  const scanRequest = runLocalScan()
    .then((data) => {
      rawData = data;
    })
    .catch((error) => {
      scanError = error;
    })
    .finally(() => {
      scanDone = true;
    });

  for (let index = 0; index < scanCategories.length && !scanDone; index += 1) {
    state.progressIndex = index;
    state.progressPercent = Math.round(((index + 0.25) / scanCategories.length) * 100);
    render();
    await wait(420);
    state.progressPercent = Math.round(((index + 1) / scanCategories.length) * 100);
    render();
    await wait(180);
  }

  while (!scanDone) {
    state.progressIndex = scanCategories.length - 1;
    state.progressPercent = Math.min(92, state.progressPercent + 3);
    render();
    await wait(450);
  }

  await scanRequest;

  if (scanError || rawData === null) {
    state.error = scanError?.message || "The local scan did not return data.";
    state.screen = "start";
    render();
    return;
  }

  try {
    state.results = normalizeScan(rawData);
  } catch (error) {
    state.error = error.message || "The scanner response does not match the BeSecured JSON contract.";
    state.screen = "start";
    render();
    return;
  }

  state.screen = "results";
  state.progressIndex = scanCategories.length;
  state.progressPercent = 100;
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
    throw new Error(detail || "Could not run the local scan. Start the UI with python -m besecured.ui.");
  }
  return response.json();
}

function normalizeScan(data) {
  requireContractKeys(data, ["schema_version", "scan_source", "generated_at", "system_info", "status_counts", "category_scores", "overall_score", "grade", "score_details", "scoring_note", "findings"]);
  const findings = Array.isArray(data.findings) ? data.findings.map(normalizeFinding) : [];
  return {
    schema_version: data.schema_version,
    scan_source: data.scan_source,
    generated_at: data.generated_at,
    system_info: data.system_info || {},
    status_counts: normalizeStatusCounts(data.status_counts, findings),
    category_scores: normalizeCategoryScores(data.category_scores),
    overall_score: clampScore(data.overall_score),
    grade: data.grade || "",
    score_details: data.score_details || {},
    scoring_note: data.scoring_note || "",
    findings: sortedFindings(findings)
  };
}

function normalizeFinding(finding, index) {
  const status = String(finding.status || "").toUpperCase();
  const safeStatus = statusOrder[status] === undefined ? "INFO" : status;
  const recommendedAction = finding.recommended_action || "Review if needed.";
  return {
    category: finding.category || "System",
    name: finding.name || `Security check ${index + 1}`,
    status: safeStatus,
    detail: finding.detail || "No detail available.",
    explanation: finding.explanation || "This item can affect the local security posture.",
    recommended_action: recommendedAction,
    fix_steps: Array.isArray(finding.fix_steps) && finding.fix_steps.length ? finding.fix_steps : [recommendedAction]
  };
}

function requireContractKeys(data, keys) {
  const missing = keys.filter((key) => data[key] === undefined);
  if (missing.length) {
    throw new Error(`ScanResult JSON missing key(s): ${missing.join(", ")}`);
  }
}

function normalizeStatusCounts(statusCounts, findings) {
  return {
    CRIT: Number(statusCounts?.CRIT ?? countStatus(findings, "CRIT")),
    WARN: Number(statusCounts?.WARN ?? countStatus(findings, "WARN")),
    INFO: Number(statusCounts?.INFO ?? countStatus(findings, "INFO")),
    OK: Number(statusCounts?.OK ?? countStatus(findings, "OK")),
    SKIP: Number(statusCounts?.SKIP ?? countStatus(findings, "SKIP"))
  };
}

function normalizeCategoryScores(categoryScores) {
  return Object.fromEntries(
    Object.entries(categoryScores || {}).map(([category, score]) => [
      category,
      score === null ? null : clampScore(score)
    ])
  );
}

function sortedFindings(findings) {
  return [...findings].sort((a, b) => {
    const rank = (statusOrder[a.status] ?? 9) - (statusOrder[b.status] ?? 9);
    if (rank !== 0) {
      return rank;
    }
    return a.name.localeCompare(b.name);
  });
}

function countStatus(findings, status) {
  return findings.filter((finding) => finding.status === status).length;
}

function statusCount(data, status) {
  return Number(data.status_counts?.[status] ?? 0);
}

function scoreSummary(data) {
  return data.score_details?.summary || data.scoring_note || "Score details unavailable.";
}

function scoreSteps(data) {
  const steps = data.score_details?.calculation_steps;
  if (Array.isArray(steps) && steps.length) {
    return steps;
  }
  return [`Final score: ${scoreFormula(data)} = ${data.overall_score}.`];
}

function scoreFormula(data) {
  return data.score_details?.formula || "100 - round(lost_points / max_points * 100)";
}

function scoreLostPoints(data) {
  return Number(data.score_details?.lost_points ?? 0);
}

function scoreMaxPoints(data) {
  return Number(data.score_details?.max_points ?? 0);
}

function statusLabel(status) {
  return {
    CRIT: "Critical",
    WARN: "Warning",
    OK: "OK",
    INFO: "Info",
    SKIP: "Skipped"
  }[status] || "Info";
}

function categoriesForResults(data) {
  const categories = Object.keys(data.category_scores || {});
  if (categories.length) {
    return categories;
  }
  return [...new Set(data.findings.map((finding) => finding.category))].sort();
}

function systemLabel(data) {
  return data.system_info?.OS || data.system_info?.System || "Unknown OS";
}

function statusText(data) {
  if (data.overall_score >= 85) {
    return "Your device looks good";
  }
  if (data.overall_score >= 60) {
    return "Some issues need attention";
  }
  return "High risk, fix these first";
}

function riskDescription(data) {
  const issueCount = statusCount(data, "CRIT") + statusCount(data, "WARN");
  if (issueCount === 0) {
    return "Passed checks dominate this local sample report.";
  }
  return `${issueCount} issue${issueCount === 1 ? "" : "s"} should be reviewed before this device is considered clean.`;
}

function sourceNotice(data) {
  if (data.scan_source !== "sample") {
    return '<div class="local-note">' + icon("lock") + " Real local scan completed.</div>";
  }
  return '<div class="demo-note">' + icon("alert") + " Prototype sample data.</div>";
}

function colorForScore(score) {
  if (score >= 85) {
    return statusColors.OK;
  }
  if (score >= 60) {
    return statusColors.WARN;
  }
  return statusColors.CRIT;
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
  anchor.download = `BeSecured-report-${String(state.results.generated_at).slice(0, 10)}.html`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  state.exported = true;
  render();
}

function renderExportHtml(data) {
  const issueCount = statusCount(data, "CRIT") + statusCount(data, "WARN");
  const issues = sortedFindings(data.findings).map((finding) => `
    <section>
      <h2>${escapeHtml(finding.name)}</h2>
      <p><strong>Severity:</strong> ${escapeHtml(statusLabel(finding.status))}</p>
      <p><strong>Category:</strong> ${escapeHtml(finding.category)}</p>
      <p><strong>What we found:</strong> ${escapeHtml(finding.detail)}</p>
      <p><strong>Why it matters:</strong> ${escapeHtml(finding.explanation)}</p>
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
      <p>Scan date: ${escapeHtml(formatDate(data.generated_at))}</p>
      <p>Operating system: ${escapeHtml(systemLabel(data))}</p>
      <p>Score: ${data.overall_score} / 100</p>
      <p>Formula: ${escapeHtml(scoreFormula(data))}</p>
      <p>Severity points: ${scoreLostPoints(data)} lost / ${scoreMaxPoints(data)} max</p>
      <p>${escapeHtml(scoreSummary(data))}</p>
      <p>Issues to review: ${issueCount}</p>
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
