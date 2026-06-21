const CHECK_AREAS = [
  "Système",
  "Ports en écoute",
  "Pare-feu",
  "Comptes",
  "Mots de passe",
  "Mises à jour",
  "Antivirus et protection",
  "Chiffrement disque",
  "Dossiers partagés",
  "Programmes au démarrage"
];

const CATEGORY_FR = {
  Accounts: "Comptes",
  Antivirus: "Antivirus",
  "Disk Encryption": "Chiffrement disque",
  "Execution Context": "Contexte d'exécution",
  Firewall: "Pare-feu",
  Network: "Réseau",
  "Open Ports": "Ports ouverts",
  "Password Policy": "Politique de mot de passe",
  "Privilege Elevation": "Élévation de privilèges",
  Protection: "Protection",
  "Shared Folders": "Dossiers partagés",
  "Startup Programs": "Programmes au démarrage",
  System: "Système",
  Updates: "Mises à jour",
  "User Accounts": "Comptes utilisateur"
};

const STATUS_FR = { CRIT: "Critique", WARN: "Avertissement", INFO: "Info", OK: "Conforme", SKIP: "Ignoré" };
const STATUS_ORDER = { CRIT: 0, WARN: 1, INFO: 2, OK: 3, SKIP: 4 };
const STATUS_CLASS = { CRIT: "crit", WARN: "warn", INFO: "info", OK: "ok", SKIP: "skip" };

const NAV = [
  { key: "summary", label: "Aperçu" },
  { key: "categories", label: "Catégories" },
  { key: "findings", label: "Points à corriger" },
  { key: "report", label: "Rapport" }
];

const PANE_TITLES = {
  start: "Diagnostic",
  scan: "Analyse",
  summary: "Aperçu",
  categories: "Catégories",
  findings: "Points à corriger",
  report: "Rapport"
};

const SHIELD = '<svg viewBox="0 0 32 32" aria-hidden="true"><path d="M16 2.5 5.5 6.6v8.1c0 6.7 4.4 11.9 10.5 14.8 6.1-2.9 10.5-8.1 10.5-14.8V6.6L16 2.5Z" fill="#2b5bb5"/><path d="m11.2 15.8 3.3 3.4 6.3-6.6" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>';

const state = {
  screen: "start",
  view: "summary",
  filter: "all",
  results: null,
  error: "",
  exported: false
};

const app = document.getElementById("app");

function render() {
  app.innerHTML = `<div class="app">${renderRail()}<main class="pane">${renderPane()}</main></div>`;
  bindEvents();
}

function renderRail() {
  const data = state.results;
  const machine = readMachine(data);
  const nav = NAV.map((item) => {
    const disabled = data ? "" : "disabled";
    const count = item.key === "findings" && data ? `<span class="c">${actionableCount(data)}</span>` : "";
    const current = state.screen === "results" && state.view === item.key ? 'aria-current="page"' : "";
    return `<button class="nav-item" data-view="${item.key}" ${disabled} ${current}><span>${item.label}</span>${count}</button>`;
  }).join("");

  return `
    <aside class="rail">
      <div class="rail-brand">
        ${SHIELD}
        <span><b>BeSecured</b><span>Diagnostic local</span></span>
      </div>
      <nav class="rail-nav">${nav}</nav>
      <div class="rail-foot">
        <dl class="machine">
          <div><span>Hôte</span><b>${escapeHtml(machine.host)}</b></div>
          <div><span>Système</span><b>${escapeHtml(machine.os)}</b></div>
        </dl>
        <p class="privacy">Aucun compte, aucun envoi. Le scan lit l'état local et reste sur 127.0.0.1.</p>
      </div>
    </aside>
  `;
}

function renderPane() {
  const title = PANE_TITLES[state.error ? "start" : state.screen === "results" ? state.view : state.screen] || "Diagnostic";
  const meta = state.screen === "results" && state.results
    ? `Scanné le ${formatDate(state.results.generated_at)}`
    : "";
  return `
    <header class="pane-bar">
      <h1 class="pane-title">${escapeHtml(title)}</h1>
      <span class="pane-meta">${escapeHtml(meta)}</span>
    </header>
    <div class="pane-body">${renderBody()}</div>
  `;
}

function renderBody() {
  if (state.error) return renderError();
  if (state.screen === "scan") return renderScan();
  if (state.screen === "results" && state.results) return renderResults();
  return renderStart();
}

function renderStart() {
  return `
    <h2 class="head">Analyser la sécurité de cet appareil</h2>
    <p class="lead">BeSecured lit les réglages de sécurité locaux, repère les faiblesses courantes et calcule un score sur 100. Rien n'est installé, rien n'est envoyé.</p>
    <div class="row"><button class="btn" data-action="start">Lancer le scan</button></div>
    <h3 class="sub">Contrôles effectués</h3>
    <ol class="areas">
      ${CHECK_AREAS.map((area, i) => `
        <li class="area"><span class="i">${pad(i + 1)}</span><span>${escapeHtml(area)}</span><span class="st">en attente</span></li>
      `).join("")}
    </ol>
  `;
}

function renderScan() {
  return `
    <h2 class="head">Lecture des réglages système</h2>
    <p class="lead">Analyse locale en cours. Cela prend quelques secondes.</p>
    <div class="progress indet" aria-label="Analyse en cours"><div class="bar"></div></div>
    <ol class="areas">
      ${CHECK_AREAS.map((area, i) => `
        <li class="area"><span class="i">${pad(i + 1)}</span><span>${escapeHtml(area)}</span><span class="st">en attente</span></li>
      `).join("")}
    </ol>
  `;
}

function renderResults() {
  if (state.view === "categories") return renderCategories();
  if (state.view === "findings") return renderFindings();
  if (state.view === "report") return renderReport();
  return renderSummary();
}

function renderSummary() {
  const data = state.results;
  const score = data.overall_score;
  const ring = colorClassForScore(score);
  const circ = 2 * Math.PI * 50;
  const offset = circ * (1 - score / 100);

  return `
    <h2 class="verdict">${escapeHtml(verdictTitle(data))}</h2>
    <p class="lead">${escapeHtml(scoreDescription(data))}</p>

    <div class="score-row">
      <svg class="gauge" viewBox="0 0 120 120" aria-label="Score ${score} sur 100">
        <circle class="gauge-track" cx="60" cy="60" r="50" fill="none" stroke-width="6"></circle>
        <circle class="gauge-val ${ring}" cx="60" cy="60" r="50" fill="none" stroke-width="6"
          stroke-dasharray="${circ.toFixed(2)}" stroke-dashoffset="${offset.toFixed(2)}" transform="rotate(-90 60 60)"></circle>
        <text class="g-num" x="60" y="62">${score}</text>
        <text class="g-out" x="60" y="80">/ 100</text>
      </svg>
      <div class="score-side">
        <p class="grade">Grade ${escapeHtml(data.grade || "non noté")}<small>${score} / 100</small></p>
        <p class="note">${escapeHtml(frenchScoreNote(data))}</p>
      </div>
    </div>

    <div class="counts">
      ${cell("CRIT", data)}${cell("WARN", data)}${cell("INFO", data)}${cell("OK", data)}${cell("SKIP", data)}
    </div>
    <p class="formula">${escapeHtml(frenchFormula(data))}</p>

    <div class="row" style="margin-top:22px">
      <button class="btn ghost" data-view="findings">Voir les points à corriger</button>
      <button class="btn ghost" data-view="report">Aller au rapport</button>
      <button class="btn ghost" data-action="start">Relancer le scan</button>
    </div>
  `;
}

function renderCategories() {
  const data = state.results;
  const rows = sortCategories(data).map((row) => `
    <tr>
      <td><span class="cn">${escapeHtml(catLabel(row.category))}</span>${row.notScored ? '<div class="cm">non noté</div>' : ""}</td>
      <td class="r">${row.notScored ? "non noté" : row.score}</td>
      <td class="r">${row.notScored ? "non noté" : `${row.lost} / ${row.max}`}</td>
      <td class="r">${row.actionable}</td>
    </tr>
  `).join("");

  return `
    <p class="lead">Score par catégorie. Une catégorie sans contrôle applicable est marquée non noté.</p>
    <table class="tbl">
      <thead><tr><th>Catégorie</th><th class="r">Score</th><th class="r">Perdus / Max</th><th class="r">À revoir</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <p class="formula">${escapeHtml(frenchFormula(data))}</p>
  `;
}

function renderFindings() {
  const data = state.results;
  const all = data.findings;
  const counts = {
    all: all.length,
    CRIT: statusCount(data, "CRIT"),
    WARN: statusCount(data, "WARN"),
    INFO: statusCount(data, "INFO"),
    OK: statusCount(data, "OK"),
    SKIP: statusCount(data, "SKIP")
  };
  const filtered = all.filter((f) => state.filter === "all" || f.status === state.filter);

  return `
    <p class="lead">Les points critiques apparaissent en premier. Filtre par statut au besoin.</p>
    <div class="filters" role="toolbar" aria-label="Filtres">
      ${chip("all", "Tout", counts.all)}
      ${chip("CRIT", "Critique", counts.CRIT)}
      ${chip("WARN", "Avertissement", counts.WARN)}
      ${chip("INFO", "Info", counts.INFO)}
      ${chip("OK", "Conforme", counts.OK)}
      ${chip("SKIP", "Ignoré", counts.SKIP)}
    </div>
    ${filtered.length === 0 ? '<div class="empty">Aucun point dans ce filtre.</div>' : `<div class="finds">${filtered.map(renderFinding).join("")}</div>`}
  `;
}

function renderFinding(f) {
  const cls = STATUS_CLASS[f.status] || "info";
  const steps = (f.fix_steps && f.fix_steps.length ? f.fix_steps : [f.how_to_fix || "Revoir si nécessaire."])
    .map((s) => `<li>${escapeHtml(s)}</li>`).join("");
  return `
    <article class="find">
      <header class="find-h">
        <span class="tag ${cls}">${STATUS_FR[f.status] || f.status}</span>
        <h3 class="find-t">${escapeHtml(f.name)}</h3>
        <span class="find-c">${escapeHtml(catLabel(f.category))}</span>
      </header>
      <dl class="find-b">
        <div class="blk"><dt>Constat</dt><dd>${escapeHtml(f.what_we_found)}</dd></div>
        <div class="blk"><dt>Pourquoi c'est important</dt><dd>${escapeHtml(f.why_it_matters)}</dd></div>
        <div class="blk"><dt>Étapes pour corriger</dt><dd><ol>${steps}</ol></dd></div>
      </dl>
      <div class="find-m">
        <span>Systèmes <b>${escapeHtml(osLabel(f.supported_os))}</b></span>
        <span>Droits <b>${f.requires_admin ? "admin" : "utilisateur"}</b></span>
      </div>
    </article>
  `;
}

function renderReport() {
  const data = state.results;
  return `
    <p class="lead">Le rapport HTML est généré dans le navigateur depuis les données du scan. Aucun envoi.</p>
    <dl class="kv">
      ${kv("Date du scan", formatDate(data.generated_at))}
      ${kv("Système", systemLabel(data))}
      ${kv("Source", data.scan_source === "scanner" ? "scanner local" : "données prototype")}
      ${kv("Score", `${data.overall_score} / 100`)}
      ${kv("Grade", data.grade || "non noté")}
      ${kv("Points perdus", `${scoreLost(data)} sur ${scoreMax(data)}`)}
      ${kv("Points à corriger", String(actionableCount(data)))}
    </dl>
    <div class="row">
      <button class="btn" data-action="export">Exporter le rapport HTML</button>
      <button class="btn ghost" data-action="start">Relancer le scan</button>
    </div>
    ${state.exported ? '<div class="hint ok">Téléchargement déclenché par le navigateur.</div>' : ""}
  `;
}

function renderError() {
  return `
    <h2 class="head">Le scan n'a pas pu aboutir</h2>
    <p class="hint err">${escapeHtml(state.error)}</p>
    <div class="row" style="margin-top:14px">
      <button class="btn" data-action="start">Réessayer</button>
      <button class="btn ghost" data-action="reset">Revenir au départ</button>
    </div>
  `;
}

function cell(status, data) {
  return `<div class="cell ${STATUS_CLASS[status]}"><span class="n">${statusCount(data, status)}</span><span class="l">${STATUS_FR[status]}</span></div>`;
}

function chip(value, label, count) {
  return `<button class="chip" data-filter="${value}" aria-pressed="${state.filter === value}">${label}<span class="c">${count}</span></button>`;
}

function kv(label, value) {
  return `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`;
}

function bindEvents() {
  app.querySelectorAll("[data-action='start']").forEach((b) => b.addEventListener("click", startScan));
  app.querySelectorAll("[data-action='export']").forEach((b) => b.addEventListener("click", exportReport));
  app.querySelectorAll("[data-action='reset']").forEach((b) => b.addEventListener("click", () => {
    state.screen = "start";
    state.error = "";
    render();
  }));
  app.querySelectorAll("[data-view]").forEach((b) => {
    if (b.disabled) return;
    b.addEventListener("click", () => {
      state.view = b.dataset.view;
      if (state.results) state.screen = "results";
      render();
    });
  });
  app.querySelectorAll("[data-filter]").forEach((b) => b.addEventListener("click", () => {
    state.filter = b.dataset.filter;
    render();
  }));
}

async function startScan() {
  state.error = "";
  state.results = null;
  state.exported = false;
  state.screen = "scan";
  state.view = "summary";
  state.filter = "all";
  render();

  const started = performance.now();
  let rawData = null;
  let scanError = null;
  try {
    rawData = await runLocalScan();
  } catch (error) {
    scanError = error;
  }

  const minVisible = 700;
  const elapsed = performance.now() - started;
  if (elapsed < minVisible) await wait(minVisible - elapsed);

  if (scanError || rawData === null) {
    state.error = scanError && scanError.message ? scanError.message : "Le scanner local n'a pas répondu.";
    state.screen = "start";
    render();
    return;
  }

  try {
    state.results = normalizeScan(rawData);
  } catch (error) {
    state.error = error.message || "La réponse du scanner ne respecte pas le contrat BeSecured.";
    state.screen = "start";
    render();
    return;
  }

  state.screen = "results";
  state.view = "summary";
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
    throw new Error(detail || "Lance l'interface avec python -m besecured.ui pour démarrer le scanner local.");
  }
  return response.json();
}

function normalizeScan(data) {
  const required = ["schema_version", "scan_source", "generated_at", "system_info", "status_counts", "category_scores", "overall_score", "grade", "score_details", "scoring_note", "findings"];
  const missing = required.filter((key) => data[key] === undefined);
  if (missing.length) {
    throw new Error(`Réponse incomplète, clés manquantes: ${missing.join(", ")}`);
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
  const what = finding.what_we_found || finding.detail || "Aucun détail disponible.";
  const why = finding.why_it_matters || finding.explanation || "Cet élément peut affecter la posture locale.";
  const how = finding.how_to_fix || finding.recommended_action || finding.remediation || "Revoir si nécessaire.";
  const supportedOs = Array.isArray(finding.supported_os) ? finding.supported_os.filter(Boolean) : ["Windows", "macOS", "Linux"];
  return {
    id: finding.id || `f-${index}`,
    category: finding.category || "System",
    name: finding.name || `Contrôle ${index + 1}`,
    status: safeStatus,
    severity_label: finding.severity_label || STATUS_FR[safeStatus],
    what_we_found: what,
    why_it_matters: why,
    how_to_fix: how,
    fix_steps: Array.isArray(finding.fix_steps) && finding.fix_steps.length ? finding.fix_steps : [how],
    supported_os: supportedOs,
    requires_admin: Boolean(finding.requires_admin)
  };
}

function normalizeStatusCounts(counts, findings) {
  return {
    CRIT: Number((counts || {}).CRIT ?? countStatus(findings, "CRIT")),
    WARN: Number((counts || {}).WARN ?? countStatus(findings, "WARN")),
    INFO: Number((counts || {}).INFO ?? countStatus(findings, "INFO")),
    OK: Number((counts || {}).OK ?? countStatus(findings, "OK")),
    SKIP: Number((counts || {}).SKIP ?? countStatus(findings, "SKIP"))
  };
}

function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const rank = (STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9);
    if (rank !== 0) return rank;
    return a.name.localeCompare(b.name);
  });
}

function sortCategories(data) {
  const details = (data.score_details && data.score_details.category_details) || {};
  const categories = Object.keys(data.category_scores || {}).sort((a, b) => catLabel(a).localeCompare(catLabel(b)));
  return categories.map((category) => {
    const score = data.category_scores[category];
    const notScored = score === null || score === undefined;
    const detail = details[category] || {};
    const actionable = data.findings.filter((f) => f.category === category && (f.status === "CRIT" || f.status === "WARN")).length;
    return {
      category,
      notScored,
      score: notScored ? null : clampScore(score),
      lost: Number(detail.lost_points ?? 0),
      max: Number(detail.max_points ?? 0),
      actionable
    };
  });
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

function readMachine(data) {
  const sys = (data && data.system_info) || {};
  return {
    host: sys.Hostname || sys.hostname || "non lu",
    os: sys.OS || sys.System || sys.os_label || "non lu"
  };
}

function catLabel(category) {
  return CATEGORY_FR[category] || category;
}

function osLabel(supportedOs) {
  if (!Array.isArray(supportedOs) || supportedOs.length === 0) return "non précisé";
  return supportedOs.join(", ");
}

function colorClassForScore(score) {
  if (score >= 85) return "ok";
  if (score >= 60) return "warn";
  return "crit";
}

function verdictTitle(data) {
  const n = actionableCount(data);
  if (n === 0) return "Aucun point à corriger";
  return `${n} point${n > 1 ? "s" : ""} à corriger`;
}

function scoreDescription(data) {
  const n = actionableCount(data);
  if (n === 0) return "Aucun point critique ni avertissement sur ce scan.";
  return `${n} point${n > 1 ? "s" : ""} à revoir, classés par gravité.`;
}

function frenchScoreNote(data) {
  const score = data.overall_score;
  const crit = statusCount(data, "CRIT");
  const warn = statusCount(data, "WARN");
  const ok = statusCount(data, "OK");
  const scored = crit + warn + ok;
  let quality;
  if (score >= 90) quality = "Posture saine";
  else if (score >= 75) quality = "Posture correcte";
  else if (score >= 60) quality = "Posture moyenne";
  else if (score >= 40) quality = "Posture faible";
  else quality = "Posture critique";

  let reason;
  if (crit) reason = `${crit} point${crit > 1 ? "s" : ""} critique${crit > 1 ? "s" : ""} pèse${crit > 1 ? "nt" : ""} le plus.`;
  else if (warn) reason = `${warn} avertissement${warn > 1 ? "s" : ""} abaisse${warn > 1 ? "nt" : ""} le score.`;
  else reason = "Tous les contrôles notés sont conformes.";

  return `${quality}. ${reason} ${ok}/${scored} contrôle${scored > 1 ? "s" : ""} noté${scored > 1 ? "s" : ""} conforme${ok > 1 ? "s" : ""}.`;
}

function frenchFormula(data) {
  const lost = scoreLost(data);
  const max = scoreMax(data);
  return `100 - round(${lost} / ${max} x 100) = ${data.overall_score}, soit ${lost} point(s) perdu(s) sur ${max}.`;
}

function scoreLost(data) {
  return Number((data.score_details || {}).lost_points ?? 0);
}

function scoreMax(data) {
  return Number((data.score_details || {}).max_points ?? 0);
}

function systemLabel(data) {
  const sys = (data && data.system_info) || {};
  return sys.OS || sys.System || sys.os_label || "OS inconnu";
}

function clampScore(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return 0;
  return Math.max(0, Math.min(100, Math.round(number)));
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("fr-FR", {
    year: "numeric", month: "long", day: "2-digit", hour: "2-digit", minute: "2-digit"
  }).format(date);
}

function exportReport() {
  const html = renderExportHtml(state.results);
  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `BeSecured-rapport-${String(state.results.generated_at).slice(0, 10)}.html`;
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
      <p><strong>Statut</strong> ${escapeHtml(STATUS_FR[f.status] || f.status)}</p>
      <p><strong>Catégorie</strong> ${escapeHtml(catLabel(f.category))}</p>
      <p><strong>Systèmes</strong> ${escapeHtml(osLabel(f.supported_os))}</p>
      <p><strong>Droits</strong> ${f.requires_admin ? "admin" : "utilisateur"}</p>
      <p><strong>Constat</strong> ${escapeHtml(f.what_we_found)}</p>
      <p><strong>Pourquoi c'est important</strong> ${escapeHtml(f.why_it_matters)}</p>
      <p><strong>Étapes pour corriger</strong></p>
      <ol>${f.fix_steps.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ol>
    </section>
  `).join("");
  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>BeSecured, rapport local</title>
  <style>
    body { margin: 0; padding: 32px; background: #e9ebee; color: #15181d; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; line-height: 1.5; }
    main { max-width: 820px; margin: 0 auto; background: #fff; padding: 28px; border: 1px solid #e4e7eb; }
    h1 { margin: 0 0 12px; font-size: 22px; }
    h2 { margin: 0 0 6px; font-size: 16px; }
    section { padding: 14px 0; border-top: 1px solid #e4e7eb; }
    section:first-of-type { border-top: 0; }
    p, ol { margin: 4px 0; font-size: 13px; }
  </style>
</head>
<body>
  <main>
    <h1>BeSecured, rapport local</h1>
    <p>Date du scan ${escapeHtml(formatDate(data.generated_at))}</p>
    <p>Système ${escapeHtml(systemLabel(data))}</p>
    <p>Score ${data.overall_score} sur 100, grade ${escapeHtml(data.grade || "")}</p>
    <p>${escapeHtml(frenchFormula(data))}</p>
    <p>Points à corriger ${actionableCount(data)}</p>
    <p>${escapeHtml(frenchScoreNote(data))}</p>
    ${findings}
  </main>
</body>
</html>`;
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
