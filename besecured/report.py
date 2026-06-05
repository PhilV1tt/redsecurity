from __future__ import annotations

import html
import json
from pathlib import Path

from .models import Finding, ScanResult


STATUS_META = {
    "CRIT": ("Critical", "#b91c1c"),
    "WARN": ("Warning", "#b45309"),
    "INFO": ("Info", "#2563eb"),
    "OK": ("OK", "#15803d"),
    "SKIP": ("Skipped", "#64748b"),
}


def write_html_report(result: ScanResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(result), encoding="utf-8")


def write_json_report(result: ScanResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")


def render_html(result: ScanResult) -> str:
    host = _escape(result.system_info.get("Hostname", "Unknown"))
    generated = _escape(result.generated_at.strftime("%Y-%m-%d %H:%M:%S %Z"))
    counts = result.status_counts
    score_details = result.score_details or {}
    category_details = score_details.get("category_details", {})
    if not isinstance(category_details, dict):
        category_details = {}
    category_rows = "\n".join(
        _category_row(name, score, category_details.get(name, {}))
        for name, score in result.category_scores.items()
    )
    finding_rows = "\n".join(_finding_row(finding) for finding in result.sorted_findings())
    factor_items = _score_factor_items(score_details)
    calculation_items = _calculation_items(score_details)
    score_model_rows = _score_model_rows(score_details)
    finding_impact_rows = _finding_impact_rows(score_details)
    system_rows = "\n".join(
        f"<tr><th>{_escape(key)}</th><td>{_escape(value)}</td></tr>"
        for key, value in result.system_info.items()
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BeSecured Report - {host}</title>
  <style>
    :root {{
      --bg: #f8fafc;
      --surface: #ffffff;
      --surface-2: #eef2f7;
      --border: #d6dee8;
      --text: #111827;
      --muted: #667085;
      --ok: #15803d;
      --warn: #b45309;
      --crit: #b91c1c;
      --info: #2563eb;
      --skip: #64748b;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.45;
    }}
    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 28px 18px 44px;
    }}
    header {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 18px;
      align-items: end;
      padding-bottom: 18px;
      border-bottom: 1px solid var(--border);
    }}
    h1, h2 {{ margin: 0; }}
    h1 {{ font-size: 2rem; letter-spacing: 0; }}
    h2 {{ font-size: 1rem; margin-bottom: 12px; }}
    h3 {{ font-size: .9rem; margin: 14px 0 8px; }}
    .subtle {{ color: var(--muted); font-size: .92rem; }}
    .score-note {{ margin-top: 0; }}
    .factors, .calculation {{
      margin: 10px 0 0;
      padding-left: 18px;
      color: var(--muted);
      font-size: .9rem;
    }}
    .factors li, .calculation li {{ margin: 5px 0; }}
    .score {{
      width: 132px;
      height: 132px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--surface);
      display: grid;
      place-items: center;
      text-align: center;
    }}
    .grade {{ font-size: 3.1rem; font-weight: 800; line-height: 1; }}
    .score small {{ display: block; color: var(--muted); margin-top: 6px; }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 14px;
      margin-top: 18px;
    }}
    section, .panel {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }}
    .privacy {{
      margin-top: 18px;
      background: #ecfdf5;
      border-color: #bbf7d0;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 8px;
    }}
    .stat {{
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px;
      background: var(--surface-2);
    }}
    .stat strong {{ display: block; font-size: 1.5rem; }}
    .stat span {{ color: var(--muted); font-size: .82rem; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: .9rem;
    }}
    th, td {{
      padding: 9px 8px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
    }}
    th {{ color: var(--muted); font-weight: 600; }}
    tr:last-child th, tr:last-child td {{ border-bottom: 0; }}
    .status {{
      display: inline-block;
      min-width: 72px;
      padding: 3px 8px;
      border-radius: 999px;
      color: white;
      font-size: .78rem;
      font-weight: 700;
      text-align: center;
    }}
    .bar {{
      height: 10px;
      background: var(--surface-2);
      border-radius: 999px;
      overflow: hidden;
    }}
    .bar span {{
      display: block;
      height: 100%;
      background: #0f766e;
    }}
    .not-scored {{ color: var(--muted); }}
    .score-impact {{ color: var(--muted); font-size: .8rem; margin: 4px 0; }}
    .impact-detail {{ color: var(--muted); font-size: .78rem; margin-top: 4px; }}
    .findings td:nth-child(1) {{ white-space: nowrap; color: #0f766e; font-weight: 650; }}
    .findings td:nth-child(3) {{ width: 92px; }}
    footer {{
      margin-top: 18px;
      color: var(--muted);
      font-size: .82rem;
      text-align: center;
    }}
    @media (max-width: 820px) {{
      header {{ grid-template-columns: 1fr; }}
      .grid {{ grid-template-columns: 1fr; }}
      .stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .score {{ width: 100%; height: auto; padding: 18px; }}
      .findings td, .findings th {{ display: block; width: 100%; }}
      .findings tr {{ display: block; border-bottom: 1px solid var(--border); padding: 8px 0; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <p class="subtle">BeSecured local cybersecurity scanner</p>
        <h1>Security Report</h1>
        <p class="subtle">Host: {host} | Scan: {generated}</p>
      </div>
      <div class="score">
        <div>
          <div class="grade">{_escape(result.grade)}</div>
          <small>{result.overall_score} / 100</small>
        </div>
      </div>
    </header>

    <section class="privacy">
      <h2>Privacy</h2>
      <p>This report was generated locally. BeSecured does not upload scan data, credentials, files or system details to an external service.</p>
      <p>No account, cloud API or remote backend is used.</p>
    </section>

    <div class="grid">
      <section>
        <h2>Summary</h2>
        <div class="stats">
          {_stat("CRIT", counts.get("CRIT", 0))}
          {_stat("WARN", counts.get("WARN", 0))}
          {_stat("INFO", counts.get("INFO", 0))}
          {_stat("OK", counts.get("OK", 0))}
          {_stat("SKIP", counts.get("SKIP", 0))}
        </div>
      </section>
      <section>
        <h2>Scoring</h2>
        <p class="subtle score-note">{_escape(result.scoring_note)}</p>
        <h3>Calculation</h3>
        <ol class="calculation">{calculation_items}</ol>
        <ul class="factors">{factor_items}</ul>
        <h3>Weight Model</h3>
        <table>{score_model_rows}</table>
        <h3>Category Impact</h3>
        <table>{category_rows}</table>
        <h3>Finding Impact</h3>
        <table>{finding_impact_rows}</table>
      </section>
      <section>
        <h2>System Info</h2>
        <table>{system_rows}</table>
      </section>
    </div>

    <section style="margin-top: 14px;">
      <h2>Detailed Findings by Severity</h2>
      <table class="findings">
        <thead>
          <tr>
            <th>Category</th>
            <th>Check</th>
            <th>Severity</th>
            <th>OS support</th>
            <th>Admin</th>
            <th>What we found</th>
            <th>Why it matters</th>
            <th>How to fix it</th>
          </tr>
        </thead>
        <tbody>
          {finding_rows}
        </tbody>
      </table>
    </section>
    <footer>Generated by BeSecured Python CLI</footer>
  </main>
</body>
</html>
"""


def _stat(status: str, count: int) -> str:
    label, color = STATUS_META[status]
    return f"<div class='stat'><strong style='color:{color}'>{count}</strong><span>{label}</span></div>"


def _category_row(name: str, score: int | None, detail: object) -> str:
    if score is None:
        value = "<span class='not-scored'>Not scored</span>"
        bar = ""
    else:
        detail_dict = detail if isinstance(detail, dict) else {}
        lost_points = int(detail_dict.get("lost_points", 0))
        max_points = int(detail_dict.get("max_points", 0))
        impacted = detail_dict.get("impacted_findings", [])
        impacted_names = []
        if isinstance(impacted, list):
            impacted_names = [
                str(item.get("name"))
                for item in impacted
                if isinstance(item, dict) and item.get("name")
            ]
        impacted_text = ", ".join(impacted_names) if impacted_names else "No warning or critical item."
        value = f"{score}%"
        impact = f"<div class='score-impact'>Severity points lost: {lost_points}/{max_points}</div>"
        detail_line = f"<div class='impact-detail'>Impacting checks: {_escape(impacted_text)}</div>"
        bar = f"{impact}{detail_line}<div class='bar'><span style='width:{score}%'></span></div>"
    return f"<tr><th>{_escape(name)}</th><td>{value}{bar}</td></tr>"


def _score_factor_items(score_details: dict[str, object]) -> str:
    factors = score_details.get("factors")
    if not isinstance(factors, list) or not factors:
        factors = ["INFO and SKIP findings are listed for context but are not scored."]
    return "".join(f"<li>{_escape(factor)}</li>" for factor in factors)


def _calculation_items(score_details: dict[str, object]) -> str:
    steps = score_details.get("calculation_steps")
    if not isinstance(steps, list) or not steps:
        steps = ["Score = 100 - round(lost_points / max_points * 100)."]
    return "".join(f"<li>{_escape(step)}</li>" for step in steps)


def _score_model_rows(score_details: dict[str, object]) -> str:
    weights = score_details.get("severity_weights")
    if not isinstance(weights, dict):
        weights = {"OK": 0, "WARN": 2, "CRIT": 5}
    rows = [
        ("CRIT", weights.get("CRIT", 5), "High risk issue. Maximum impact."),
        ("WARN", weights.get("WARN", 2), "Weakness to fix. Medium impact."),
        ("INFO", 0, "Shown for context but ignored by the score."),
        ("OK", weights.get("OK", 0), "Passed check. No points lost."),
        ("SKIP", 0, "Unsupported or unavailable check. Ignored by the score."),
    ]
    return "".join(
        f"<tr><th>{_escape(status)}</th><td>{_escape(weight)} severity point(s)</td><td>{_escape(note)}</td></tr>"
        for status, weight, note in rows
    )


def _finding_impact_rows(score_details: dict[str, object]) -> str:
    impacts = score_details.get("finding_impacts")
    if not isinstance(impacts, list) or not impacts:
        return "<tr><td colspan='4'><span class='not-scored'>No scored finding impact available.</span></td></tr>"

    rows = []
    for item in impacts:
        if not isinstance(item, dict):
            continue
        points = int(item.get("severity_points", 0))
        if points <= 0:
            continue
        rows.append(
            "<tr>"
            f"<th>{_escape(item.get('category', ''))}</th>"
            f"<td>{_escape(item.get('name', ''))}</td>"
            f"<td>{_escape(item.get('status', ''))}</td>"
            f"<td>{points} point(s), {_escape(item.get('score_impact_percent', 0))}% of the score scale</td>"
            "</tr>"
        )
    if not rows:
        return "<tr><td colspan='4'><span class='not-scored'>No warning or critical finding removed points.</span></td></tr>"
    return "".join(rows)


def _finding_row(finding: Finding) -> str:
    label, color = STATUS_META[finding.status]
    return (
        "<tr>"
        f"<td>{_escape(finding.category)}</td>"
        f"<td>{_escape(finding.name)}</td>"
        f"<td><span class='status' style='background:{color}'>{_escape(label)}</span></td>"
        f"<td>{_escape(_os_support_text(finding))}</td>"
        f"<td>{_escape(_admin_text(finding))}</td>"
        f"<td>{_escape(finding.what_we_found)}</td>"
        f"<td>{_escape(finding.why_it_matters)}</td>"
        f"<td>{_escape(finding.how_to_fix)}</td>"
        "</tr>"
    )


def _os_support_text(finding: Finding) -> str:
    return ", ".join(finding.supported_os) if finding.supported_os else "Unsupported"


def _admin_text(finding: Finding) -> str:
    return "Required" if finding.requires_admin else "Not required"


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)
