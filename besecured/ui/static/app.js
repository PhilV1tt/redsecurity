const SCAN_CATEGORIES = [
  "Network",
  "Open Ports",
  "Firewall",
  "Antivirus",
  "Disk Encryption",
  "Accounts",
  "Protection",
  "Execution Context",
  "System",
  "Updates"
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

const STATUS_FR = {
  CRIT: "Critique",
  WARN: "Avertissement",
  INFO: "Info",
  OK: "Conforme",
  SKIP: "Ignoré"
};

const STATUS_ORDER = { CRIT: 0, WARN: 1, INFO: 2, OK: 3, SKIP: 4 };
const STATUS_CLASS = { CRIT: "crit", WARN: "warn", INFO: "info", OK: "ok", SKIP: "skip" };

const NAV = [
  { key: "summary", label: "Aperçu" },
  { key: "categories", label: "Catégories" },
  { key: "findings", label: "Points à corriger" },
  { key: "report", label: "Rapport" }
];

const state = {
  screen: "start",
  view: "summary",
  filter: "all",
  progressIndex: 0,
  progressPercent: 0,
  scanLabel: "",
  results: null,
  error: "",
  exported: false
};

const app = document.getElementById("app");

function render() {
  app.innerHTML = `
    <div class="layout">
      ${renderSidebar()}
      <main class="main">${renderMain()}</main>
    </div>
  `;
  bindEvents();
}

function renderSidebar() {
  const data = state.results;
  const machine = readMachine(data);
  const navHTML = NAV.map((item) => {
    const disabled = !data ? "disabled" : "";
    const count = item.key === "findings" && data ? actionableCount(data) : "";
    const current = state.screen === "results" && state.view === item.key ? 'aria-current="page"' : "";
    return `
      <li>
        <button class="nav-item" data-view="${item.key}" ${disabled} ${current}>
          <span>${item.label}</span>
          ${count !== "" ? `<span class="nav-count">${count}</span>` : ""}
        </button>
      </li>
    `;
  }).join("");

  return `
    <aside class="sidebar">
      <div class="brand">
        <span class="brand-name">BeSecured</span>
        <span class="brand-sub">Posture cyber, scan local</span>
      </div>
      <dl class="machine">
        <div><span>Hôte</span><strong>${escapeHtml(machine.host)}</strong></div>
        <div><span>Système</span><strong>${escapeHtml(machine.os)}</strong></div>
        <div><span>Portée</span><strong>cet appareil</strong></div>
      </dl>
      <div class="divider"></div>
      <ul class="nav">${navHTML}</ul>
      <div class="divider"></div>
      <div class="note">
        <p>Aucun compte, aucun envoi.</p>
        <p>Le scan reste sur la machine.</p>
      </div>
    </aside>
  `;
}

function renderMain() {
  if (state.error) return renderError();
  if (state.screen === "scan") return renderScan();
  if (state.screen === "results" && state.results) return renderResults();
  return renderStart();
}

function renderStart() {
  return `
    <section>
      <span class="eyebrow">Présentation</span>
      <h1 class="title">Vérifier la posture de cet appareil</h1>
      <p class="lede">BeSecured lit l'état local de la machine, mesure les points faibles courants et propose des corrections. Tout reste sur 127.0.0.1, aucune donnée ne sort.</p>

      <div class="actions">
        <button class="cta" data-action="start">Lancer le scan</button>
      </div>

      <h2 class="section-title">Ce qui sera vérifié</h2>
      <ol class="scan-list">
        ${SCAN_CATEGORIES.map((category, index) => `
          <li class="scan-row">
            <span class="idx">${pad(index + 1)}</span>
            <span>${escapeHtml(catLabel(category))}</span>
            <span class="state">en attente</span>
          </li>
        `).join("")}
      </ol>
    </section>
  `;
}

function renderScan() {
  return `
    <section>
      <span class="eyebrow">Scan en cours</span>
      <h1 class="title">Lecture des réglages locaux</h1>
      <p class="lede">${escapeHtml(state.scanLabel || "Acquisition des données système.")}</p>

      <div class="scan-progress" aria-label="Progression du scan">
        <div class="scan-progress-fill" style="width:${state.progressPercent}%"></div>
      </div>

      <ol class="scan-list">
        ${SCAN_CATEGORIES.map((category, index) => {
          const cls = index < state.progressIndex ? "done" : index === state.progressIndex ? "active" : "";
          const stateText = index < state.progressIndex ? "ok" : index === state.progressIndex ? "en cours" : "en attente";
          return `
            <li class="scan-row ${cls}">
              <span class="idx">${pad(index + 1)}</span>
              <span>${escapeHtml(catLabel(category))}</span>
              <span class="state">${stateText}</span>
            </li>
          `;
        }).join("")}
      </ol>
    </section>
  `;
}

function renderResults() {
  if (state.view === "categories") return renderCategoriesView();
  if (state.view === "findings") return renderFindingsView();
  if (state.view === "report") return renderReportView();
  return renderSummaryView();
}

function renderSummaryView() {
  const data = state.results;
  const score = data.overall_score;
  const grade = data.grade || "";
  const ringClass = colorClassForScore(score);
  const ringCirc = 2 * Math.PI * 50;
  const offset = ringCirc * (1 - score / 100);
  const summaryText = scoreHeadline(score);

  return `
    <section>
      <span class="eyebrow">Aperçu</span>
      <h1 class="title">${escapeHtml(summaryText)}</h1>
      <p class="lede">${escapeHtml(scoreDescription(data))}</p>

      <div class="score-block">
        <svg class="score-ring" viewBox="0 0 120 120" aria-label="Score ${score} sur 100">
          <circle class="score-ring-track" cx="60" cy="60" r="50" fill="none" stroke-width="6"></circle>
          <circle class="score-ring-value ${ringClass}" cx="60" cy="60" r="50" fill="none" stroke-width="6"
            stroke-linecap="butt"
            stroke-dasharray="${ringCirc.toFixed(2)}"
            stroke-dashoffset="${offset.toFixed(2)}"
            transform="rotate(-90 60 60)"></circle>
          <text class="score-figure score-figure-number" x="60" y="62">${score}</text>
          <text class="score-figure score-figure-out" x="60" y="80">/ 100</text>
        </svg>
        <div class="score-side">
          <span class="eyebrow">Grade</span>
          <p class="score-grade">${escapeHtml(grade || "non noté")}</p>
          <p class="score-summary">${escapeHtml(scoreSummaryText(data))}</p>
        </div>
      </div>

      <div class="counts" role="list" aria-label="Répartition des statuts">
        ${countCell("CRIT", data)}
        ${countCell("WARN", data)}
        ${countCell("INFO", data)}
        ${countCell("OK", data)}
        ${countCell("SKIP", data)}
      </div>

      <p class="score-formula">${escapeHtml(scoreFormula(data))} = ${score}, points perdus ${scoreLost(data)} sur ${scoreMax(data)}</p>

      <div class="actions" style="margin-top:24px">
        <button class="cta ghost" data-view="findings">Voir les points à corriger</button>
        <button class="cta ghost" data-view="report">Aller au rapport</button>
        <button class="cta ghost" data-action="start">Relancer le scan</button>
      </div>
    </section>
  `;
}

function renderCategoriesView() {
  const data = state.results;
  const categories = sortCategories(data);
  return `
    <section>
      <span class="eyebrow">Catégories</span>
      <h1 class="title">Score par catégorie</h1>
      <p class="lede">Les catégories sans contrôle applicable sont marquées non noté.</p>

      <table class="cat-table">
        <thead>
          <tr>
            <th>Catégorie</th>
            <th>Score</th>
            <th>Perdus / Max</th>
            <th>À revoir</th>
          </tr>
        </thead>
        <tbody>
          ${categories.map((row) => `
            <tr>
              <td>
                <span class="cat-name">${escapeHtml(catLabel(row.category))}</span>
                ${row.notScored ? '<div class="cat-meta">non noté</div>' : ""}
              </td>
              <td class="num">${row.notScored ? "non noté" : row.score}</td>
              <td class="num">${row.notScored ? "non noté" : `${row.lost} / ${row.max}`}</td>
              <td class="num">${row.actionable}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>

      <p class="score-formula">${escapeHtml(scoreFormula(data))}, score global ${data.overall_score} sur 100.</p>
    </section>
  `;
}

function renderFindingsView() {
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
  const filtered = all.filter((finding) => state.filter === "all" || finding.status === state.filter);

  return `
    <section>
      <span class="eyebrow">Points à corriger</span>
      <h1 class="title">${counts.CRIT + counts.WARN} point(s) à traiter</h1>
      <p class="lede">Les éléments critiques apparaissent en premier. Filtre par statut si tu cherches autre chose.</p>

      <div class="filters" role="toolbar" aria-label="Filtres">
        ${filterButton("all", "Tout", counts.all)}
        ${filterButton("CRIT", "Critique", counts.CRIT)}
        ${filterButton("WARN", "Avertissement", counts.WARN)}
        ${filterButton("INFO", "Info", counts.INFO)}
        ${filterButton("OK", "Conforme", counts.OK)}
        ${filterButton("SKIP", "Ignoré", counts.SKIP)}
      </div>

      ${filtered.length === 0 ? '<div class="empty">Aucun point dans ce filtre.</div>' : `
        <div class="findings">
          ${filtered.map(renderFinding).join("")}
        </div>
      `}
    </section>
  `;
}

function renderFinding(finding) {
  const cls = STATUS_CLASS[finding.status] || "info";
  const steps = (finding.fix_steps && finding.fix_steps.length ? finding.fix_steps : [finding.how_to_fix || "Revoir si nécessaire."])
    .map((step) => `<li>${escapeHtml(step)}</li>`).join("");
  return `
    <article class="finding">
      <header class="finding-head">
        <span class="status-tag ${cls}">${STATUS_FR[finding.status] || finding.status}</span>
        <h2 class="finding-title">${escapeHtml(finding.name)}</h2>
        <span class="finding-cat">${escapeHtml(catLabel(finding.category))}</span>
      </header>
      <dl class="finding-body">
        <div class="finding-block">
          <dt>Constat</dt>
          <dd>${escapeHtml(finding.what_we_found)}</dd>
        </div>
        <div class="finding-block">
          <dt>Pourquoi c'est important</dt>
          <dd>${escapeHtml(finding.why_it_matters)}</dd>
        </div>
        <div class="finding-block">
          <dt>Étapes pour corriger</dt>
          <dd><ol>${steps}</ol></dd>
        </div>
      </dl>
      <div class="finding-meta">
        <span>OS supportés <strong>${escapeHtml(osLabel(finding.supported_os))}</strong></span>
        <span>Droits <strong>${finding.requires_admin ? "admin" : "utilisateur"}</strong></span>
      </div>
    </article>
  `;
}

function renderReportView() {
  const data = state.results;
  const actionable = actionableCount(data);
  return `
    <section>
      <span class="eyebrow">Rapport</span>
      <h1 class="title">Exporter le rapport</h1>
      <p class="lede">Le rapport HTML est généré dans le navigateur depuis les données du scan. Aucun envoi.</p>

      <dl class="kv">
        ${kvRow("Date du scan", formatDate(data.generated_at))}
        ${kvRow("Système", systemLabel(data))}
        ${kvRow("Source", data.scan_source === "scanner" ? "scanner local" : "données prototype")}
        ${kvRow("Score", `${data.overall_score} / 100`)}
        ${kvRow("Grade", data.grade || "non noté")}
        ${kvRow("Formule", scoreFormula(data))}
        ${kvRow("Points perdus", `${scoreLost(data)} sur ${scoreMax(data)}`)}
        ${kvRow("Points à traiter", String(actionable))}
        ${kvRow("Version du schéma", data.schema_version || "non précisée")}
      </dl>

      <div class="report-actions">
        <button class="cta" data-action="export">Exporter le rapport HTML</button>
        <button class="cta ghost" data-action="start">Relancer le scan</button>
      </div>

      ${state.exported ? '<div class="export-ok">Téléchargement déclenché par le navigateur.</div>' : ""}
    </section>
  `;
}

function renderError() {
  return `
    <section>
      <span class="eyebrow">Erreur</span>
      <h1 class="title">Le scan n'a pas pu aboutir</h1>
      <p class="hint error">${escapeHtml(state.error)}</p>
      <div class="actions" style="margin-top:16px">
        <button class="cta" data-action="start">Réessayer</button>
        <button class="cta ghost" data-action="reset">Revenir à l'accueil</button>
      </div>
    </section>
  `;
}

function countCell(status, data) {
  return `
    <div class="count-cell is-${STATUS_CLASS[status]}" role="listitem">
      <span class="num">${statusCount(data, status)}</span>
      <span class="lbl">${STATUS_FR[status]}</span>
    </div>
  `;
}

function filterButton(value, label, count) {
  const pressed = state.filter === value;
  return `<button class="filter" data-filter="${value}" aria-pressed="${pressed}">${label}<span class="count">${count}</span></button>`;
}

function kvRow(label, value) {
  return `<div class="kv-row"><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`;
}

function bindEvents() {
  app.querySelectorAll("[data-action='start']").forEach((button) => {
    button.addEventListener("click", startScan);
  });
  app.querySelectorAll("[data-action='reset']").forEach((button) => {
    button.addEventListener("click", () => {
      state.screen = "start";
      state.error = "";
      render();
    });
  });
  app.querySelectorAll("[data-action='export']").forEach((button) => {
    button.addEventListener("click", exportReport);
  });
  app.querySelectorAll("[data-view]").forEach((button) => {
    if (button.disabled) return;
    button.addEventListener("click", () => {
      state.view = button.dataset.view;
      if (state.results) state.screen = "results";
      render();
    });
  });
  app.querySelectorAll("[data-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      state.filter = button.dataset.filter;
      render();
    });
  });
}

async function startScan() {
  state.error = "";
  state.results = null;
  state.exported = false;
  state.screen = "scan";
  state.view = "summary";
  state.filter = "all";
  state.progressIndex = 0;
  state.progressPercent = 6;
  state.scanLabel = `Lecture, ${catLabel(SCAN_CATEGORIES[0])}.`;
  render();

  let rawData = null;
  let scanError = null;
  let scanDone = false;

  const scanRequest = runLocalScan()
    .then((data) => { rawData = data; })
    .catch((error) => { scanError = error; })
    .finally(() => { scanDone = true; });

  for (let index = 0; index < SCAN_CATEGORIES.length && !scanDone; index += 1) {
    state.progressIndex = index;
    state.progressPercent = Math.round(((index + 0.4) / SCAN_CATEGORIES.length) * 100);
    state.scanLabel = `Lecture, ${catLabel(SCAN_CATEGORIES[index])}.`;
    render();
    await wait(280);
    state.progressPercent = Math.round(((index + 1) / SCAN_CATEGORIES.length) * 100);
    render();
    await wait(140);
  }

  while (!scanDone) {
    state.progressIndex = SCAN_CATEGORIES.length - 1;
    state.progressPercent = Math.min(94, state.progressPercent + 2);
    render();
    await wait(360);
  }

  await scanRequest;

  if (scanError || rawData === null) {
    state.error = (scanError && scanError.message) ? scanError.message : "Le scanner local n'a pas répondu.";
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
  state.progressIndex = SCAN_CATEGORIES.length;
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
  const supportedOs = Array.isArray(finding.supported_os)
    ? finding.supported_os.filter(Boolean)
    : ["Windows", "macOS", "Linux"];
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
    const actionable = data.findings.filter((finding) => finding.category === category && (finding.status === "CRIT" || finding.status === "WARN")).length;
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
  return findings.filter((finding) => finding.status === status).length;
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

function scoreHeadline(score) {
  if (score >= 90) return "Posture saine";
  if (score >= 75) return "Quelques points à corriger";
  if (score >= 60) return "Plusieurs corrections recommandées";
  if (score >= 40) return "Posture faible";
  return "Posture critique";
}

function scoreDescription(data) {
  const actionable = actionableCount(data);
  if (actionable === 0) {
    return "Aucun point critique ni avertissement détecté sur ce scan.";
  }
  return `${actionable} point(s) à revoir avant de considérer la machine propre.`;
}

function scoreSummaryText(data) {
  return data.scoring_note || (data.score_details && data.score_details.summary) || "Détail du score indisponible.";
}

function scoreFormula(data) {
  return (data.score_details && data.score_details.formula) || "100 - round(perdus / max * 100)";
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
    year: "numeric",
    month: "long",
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
  anchor.download = `BeSecured-rapport-${String(state.results.generated_at).slice(0, 10)}.html`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  state.exported = true;
  render();
}

function renderExportHtml(data) {
  const actionable = actionableCount(data);
  const findings = data.findings.map((finding) => `
    <section>
      <h2>${escapeHtml(finding.name)}</h2>
      <p><strong>Statut</strong> ${escapeHtml(STATUS_FR[finding.status] || finding.status)}</p>
      <p><strong>Catégorie</strong> ${escapeHtml(catLabel(finding.category))}</p>
      <p><strong>OS supportés</strong> ${escapeHtml(osLabel(finding.supported_os))}</p>
      <p><strong>Droits</strong> ${finding.requires_admin ? "admin" : "utilisateur"}</p>
      <p><strong>Constat</strong> ${escapeHtml(finding.what_we_found)}</p>
      <p><strong>Pourquoi c'est important</strong> ${escapeHtml(finding.why_it_matters)}</p>
      <p><strong>Étapes pour corriger</strong></p>
      <ol>${finding.fix_steps.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ol>
    </section>
  `).join("");
  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <title>BeSecured, rapport local</title>
  <style>
    body { margin: 0; padding: 32px; background: #E8E9EC; color: #1A1D21; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; line-height: 1.5; }
    main { max-width: 820px; margin: 0 auto; background: #F4F5F7; padding: 28px; border: 1px solid #D5D7DA; }
    h1 { margin: 0 0 12px; font-size: 22px; }
    h2 { margin: 0 0 6px; font-size: 16px; }
    section { padding: 14px 0; border-top: 1px solid #D5D7DA; }
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
    <p>Formule ${escapeHtml(scoreFormula(data))}</p>
    <p>Points perdus ${scoreLost(data)} sur ${scoreMax(data)}</p>
    <p>Points à traiter ${actionable}</p>
    <p>${escapeHtml(scoreSummaryText(data))}</p>
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
