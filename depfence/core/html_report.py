"""Self-contained HTML security report generator."""

from __future__ import annotations

import html
from datetime import datetime, timezone

from depfence.core.models import Finding, FindingType, ScanResult, Severity

__version__ = "0.3.0"

# ---------------------------------------------------------------------------
# Display configuration
# ---------------------------------------------------------------------------

_SEV_CONFIG = {
    "CRITICAL": {"color": "#ff4d4f", "bg": "#3d0a0a", "label": "CRITICAL"},
    "HIGH":     {"color": "#ff7a45", "bg": "#3d1800", "label": "HIGH"},
    "MEDIUM":   {"color": "#ffc53d", "bg": "#3d2900", "label": "MEDIUM"},
    "LOW":      {"color": "#52c41a", "bg": "#0a2900", "label": "LOW"},
    "INFO":     {"color": "#1890ff", "bg": "#001d40", "label": "INFO"},
}

_STATUS_CONFIG = {
    "CRITICAL": {"color": "#ff4d4f", "icon": "&#x2715;", "label": "CRITICAL"},
    "WARN":     {"color": "#ffc53d", "icon": "&#x26a0;", "label": "WARN"},
    "PASS":     {"color": "#52c41a", "icon": "&#x2713;", "label": "PASS"},
}

_GRADE_CONFIG = {
    "A": {"color": "#52c41a", "bg": "#0a2900"},
    "B": {"color": "#73d13d", "bg": "#112200"},
    "C": {"color": "#ffc53d", "bg": "#3d2900"},
    "D": {"color": "#ff7a45", "bg": "#3d1800"},
    "F": {"color": "#ff4d4f", "bg": "#3d0a0a"},
}

_FINDING_TYPE_LABELS = {
    "known_vulnerability":       "Known Vulnerability",
    "malicious_package":         "Malicious Package",
    "typosquat":                 "Typosquatting",
    "behavioral_anomaly":        "Behavioral Anomaly",
    "suspicious_install_script": "Suspicious Install Script",
    "maintainer_risk":           "Maintainer Risk",
    "low_reputation":            "Low Reputation",
    "license_risk":              "License Risk",
    "provenance_missing":        "Provenance Missing",
    "deprecated":                "Deprecated",
    "slopsquat_candidate":       "Slopsquat Candidate",
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _h(text: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(text), quote=True)


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        key = f.severity.name.upper()
        counts[key] = counts.get(key, 0) + 1
    return counts


def _compute_grade(counts: dict[str, int]) -> str:
    if counts["CRITICAL"] > 0:
        return "F"
    if counts["HIGH"] >= 5:
        return "D"
    if counts["HIGH"] >= 1:
        return "C"
    if counts["MEDIUM"] >= 5:
        return "C"
    if counts["MEDIUM"] >= 1:
        return "B"
    return "A"


def _determine_status(findings: list[Finding]) -> str:
    counts = _count_by_severity(findings)
    if counts["CRITICAL"] > 0:
        return "CRITICAL"
    if counts["HIGH"] > 0:
        return "WARN"
    return "PASS"


# ---------------------------------------------------------------------------
# Badge helpers (kept for backward compatibility with existing tests)
# ---------------------------------------------------------------------------

def _sev_badge(severity: str) -> str:
    cfg = _SEV_CONFIG.get(severity.upper(), _SEV_CONFIG["INFO"])
    return (
        f'<span class="badge badge-{severity.lower()}" '
        f'style="background:{cfg["bg"]};color:{cfg["color"]};'
        f'border:1px solid {cfg["color"]};">'
        f'{cfg["label"]}</span>'
    )


def _status_badge(status: str) -> str:
    cfg = _STATUS_CONFIG.get(status, _STATUS_CONFIG["PASS"])
    return (
        f'<span class="status-badge" '
        f'style="background:{cfg["color"]}22;color:{cfg["color"]};'
        f'border:2px solid {cfg["color"]};padding:6px 18px;border-radius:20px;'
        f'font-size:1rem;font-weight:700;letter-spacing:0.08em;">'
        f'{cfg["icon"]} {cfg["label"]}</span>'
    )


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_header(
    project_name: str,
    scan_date: str,
    target: str,
    packages_scanned: int,
    grade: str,
    status: str,
) -> str:
    gcfg = _GRADE_CONFIG.get(grade, _GRADE_CONFIG["F"])
    scfg = _STATUS_CONFIG.get(status, _STATUS_CONFIG["PASS"])
    return f"""
  <header class="report-header">
    <div class="header-left">
      <div class="depfence-brand">depfence security report</div>
      <h1 class="project-name">{_h(project_name)}</h1>
      <div class="header-meta">
        <span>Scanned <strong>{_h(scan_date)}</strong></span>
        <span class="sep">&middot;</span>
        <span>{_h(target)}</span>
        <span class="sep">&middot;</span>
        <span><strong>{packages_scanned}</strong> packages</span>
      </div>
    </div>
    <div class="header-right">
      <div class="grade-badge"
           style="background:{gcfg['bg']};border-color:{gcfg['color']};color:{gcfg['color']};"
           title="Overall security grade">
        <div class="grade-letter">{grade}</div>
        <div class="grade-label">Grade</div>
      </div>
      <div class="status-pill"
           style="background:{scfg['color']}22;color:{scfg['color']};border-color:{scfg['color']};">
        {scfg['icon']} {scfg['label']}
      </div>
    </div>
  </header>"""


def _build_executive_summary(
    counts: dict[str, int],
    packages_scanned: int,
    total_findings: int,
    epss_high_count: int,
    kev_count: int,
) -> str:
    cards = [
        ("card-critical", str(counts["CRITICAL"]), "Critical"),
        ("card-high",     str(counts["HIGH"]),     "High"),
        ("card-medium",   str(counts["MEDIUM"]),   "Medium"),
        ("card-low",      str(counts["LOW"]),       "Low"),
        ("card-epss",     str(epss_high_count),     "EPSS &gt;0.5"),
        ("card-kev",      str(kev_count),           "In KEV"),
        ("card-total",    str(total_findings),      "Total Findings"),
        ("card-pkgs",     str(packages_scanned),    "Packages Scanned"),
    ]
    card_html = "\n".join(
        f'    <div class="card {cls}">'
        f'<div class="card-value">{val}</div>'
        f'<div class="card-label">{lbl}</div>'
        f'</div>'
        for cls, val, lbl in cards
    )
    return f"""
  <section class="report-section" id="section-executive-summary">
    <h2 class="section-heading">Executive Summary</h2>
    <div class="summary-grid">
{card_html}
    </div>
  </section>"""


def _build_severity_breakdown(counts: dict[str, int]) -> str:
    total = sum(counts.values()) or 1
    bars = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        cfg = _SEV_CONFIG[sev]
        cnt = counts[sev]
        pct = cnt / total * 100
        bars.append(
            f'    <div class="bar-row">'
            f'<span class="bar-label">{sev}</span>'
            f'<div class="bar-track">'
            f'<div class="bar-fill" style="width:{pct:.1f}%;background:{cfg["color"]};"></div>'
            f'</div>'
            f'<span class="bar-count" style="color:{cfg["color"]};">{cnt}</span>'
            f'</div>'
        )
    return f"""
  <section class="report-section" id="section-severity-breakdown">
    <h2 class="section-heading">Severity Breakdown</h2>
    <div class="bar-chart">
{"".join(bars)}
    </div>
  </section>"""


def _build_findings_table(sorted_findings: list[Finding]) -> str:
    if not sorted_findings:
        return f"""
  <section class="report-section" id="section-findings">
    <h2 class="section-heading">Findings</h2>
    <div class="table-wrap">
      <table class="findings-table">
        <thead><tr>
          <th>Severity</th><th>Package</th><th>CVE / ID</th>
          <th>Title</th><th>Type</th><th>Fix Version</th><th>EPSS</th>
        </tr></thead>
        <tbody>
          <tr><td colspan="7" class="no-findings">
            <span class="clean-icon">&#x2713;</span>
            No security issues found &mdash; this project looks clean!
          </td></tr>
        </tbody>
      </table>
    </div>
  </section>"""

    rows = []
    for f in sorted_findings:
        sev = f.severity.name.upper()
        pkg_name = _h(f.package.name)
        pkg_ver = _h(f.package.version or "")
        pkg_display = f"{pkg_name}@{pkg_ver}" if pkg_ver else pkg_name
        eco = _h(f.package.ecosystem)
        cve = _h(f.cve or "")
        cve_cell = (
            f'<span class="cve-tag">{cve}</span>' if cve
            else '<span class="none-dash">&mdash;</span>'
        )
        title = _h(f.title)
        ftype_label = _h(_FINDING_TYPE_LABELS.get(f.finding_type.value, f.finding_type.value))
        fix = _h(f.fix_version or "")
        fix_cell = (
            f'<span class="fix-tag">&#8594; {fix}</span>' if fix
            else '<span class="none-dash">&mdash;</span>'
        )
        epss = f.metadata.get("epss_score")
        if epss is not None:
            try:
                epss_val = float(epss)
                epss_cls = "epss-high" if epss_val >= 0.5 else "epss-med" if epss_val >= 0.1 else ""
                epss_cell = f'<span class="epss-score {epss_cls}">{epss_val:.3f}</span>'
            except (TypeError, ValueError):
                epss_cell = '<span class="none-dash">&mdash;</span>'
        else:
            epss_cell = '<span class="none-dash">&mdash;</span>'

        rows.append(
            f'    <tr data-severity="{sev.lower()}" data-ecosystem="{eco.lower()}">'
            f'<td>{_sev_badge(sev)}</td>'
            f'<td><code class="pkg-name">{pkg_display}</code>'
            f'<span class="eco-tag eco-{eco.lower()}">{eco}</span></td>'
            f'<td>{cve_cell}</td>'
            f'<td class="title-cell" title="{_h(f.detail)}">{title}</td>'
            f'<td><span class="type-tag">{ftype_label}</span></td>'
            f'<td>{fix_cell}</td>'
            f'<td>{epss_cell}</td>'
            f'</tr>'
        )

    ecosystems = sorted({f.package.ecosystem for f in sorted_findings})
    eco_options = '<option value="all">All Ecosystems</option>' + "".join(
        f'<option value="{_h(e.lower())}">{_h(e)}</option>' for e in ecosystems
    )

    return f"""
  <section class="report-section" id="section-findings">
    <h2 class="section-heading">Findings</h2>
    <div class="filter-bar">
      <label>Severity</label>
      <select id="filter-sev" onchange="applyFilters()">
        <option value="all">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
      </select>
      <label>Ecosystem</label>
      <select id="filter-eco" onchange="applyFilters()">{eco_options}</select>
      <input type="text" id="filter-search" placeholder="Search packages, CVEs, titles&hellip;" oninput="applyFilters()">
      <button class="btn-clear" onclick="clearFilters()">Clear</button>
      <span id="filter-count"></span>
    </div>
    <div class="table-wrap">
      <table class="findings-table" id="main-table">
        <thead><tr>
          <th>Severity</th><th>Package</th><th>CVE / ID</th>
          <th>Title</th><th>Type</th><th>Fix Version</th><th>EPSS</th>
        </tr></thead>
        <tbody id="main-tbody">
{"".join(rows)}
        </tbody>
      </table>
    </div>
  </section>"""


def _build_detection_categories(findings: list[Finding]) -> str:
    if not findings:
        return ""
    groups: dict[str, int] = {}
    for f in findings:
        label = _FINDING_TYPE_LABELS.get(f.finding_type.value, f.finding_type.value)
        groups[label] = groups.get(label, 0) + 1

    total = sum(groups.values()) or 1
    palette = [
        "#ff4d4f", "#ff7a45", "#ffc53d", "#52c41a", "#1890ff",
        "#722ed1", "#eb2f96", "#13c2c2", "#fa8c16", "#a0d911",
    ]
    angle = 0.0
    stops = []
    legend_rows = []
    for i, (label, cnt) in enumerate(sorted(groups.items(), key=lambda x: -x[1])):
        color = palette[i % len(palette)]
        pct = cnt / total * 100
        end_angle = angle + pct * 3.6
        stops.append(f"{color} {angle:.1f}deg {end_angle:.1f}deg")
        legend_rows.append(
            f'      <div class="legend-row">'
            f'<span class="legend-dot" style="background:{color};"></span>'
            f'<span class="legend-label">{_h(label)}</span>'
            f'<span class="legend-count">{cnt}</span>'
            f'</div>'
        )
        angle = end_angle

    return f"""
  <section class="report-section" id="section-detection-categories">
    <h2 class="section-heading">Detection Categories</h2>
    <div class="donut-wrapper">
      <div class="donut" style="background: conic-gradient({", ".join(stops)});"></div>
      <div class="donut-legend">
{"".join(legend_rows)}
      </div>
    </div>
  </section>"""


def _build_supply_chain_health(enrichments: dict | None) -> str:
    if not enrichments:
        return ""
    health = enrichments.get("supply_chain_health")
    if not health:
        return ""
    checks = health if isinstance(health, list) else health.get("checks", [])
    if not checks:
        return ""
    rows = []
    for check in checks:
        name = _h(str(check.get("name", "")))
        status = str(check.get("status", "PASS")).upper()
        detail = _h(str(check.get("detail", "")))
        scfg = _STATUS_CONFIG.get(status, _STATUS_CONFIG["PASS"])
        badge = (
            f'<span class="health-badge" '
            f'style="color:{scfg["color"]};background:{scfg["color"]}22;'
            f'border-color:{scfg["color"]};">'
            f'{scfg["icon"]} {status}</span>'
        )
        rows.append(
            f'    <tr><td>{name}</td><td>{badge}</td>'
            f'<td class="detail-cell">{detail}</td></tr>'
        )
    return f"""
  <section class="report-section" id="section-supply-chain-health">
    <h2 class="section-heading">Supply Chain Health</h2>
    <div class="table-wrap">
      <table class="findings-table">
        <thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
        <tbody>
{"".join(rows)}
        </tbody>
      </table>
    </div>
  </section>"""


def _build_recommendations(findings: list[Finding]) -> str:
    recs: list[str] = []
    counts = _count_by_severity(findings)

    fixable = [
        f for f in findings
        if f.fix_version and f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    if fixable:
        names = ", ".join(
            f"<code>{_h(f.package.name)}</code> &#8594; <code>{_h(f.fix_version)}</code>"
            for f in sorted(fixable, key=lambda x: _SEV_ORDER.get(x.severity.name.upper(), 9))[:3]
        )
        recs.append(
            f"<strong>Update vulnerable packages immediately.</strong> "
            f"Fix versions are available: {names}."
        )

    if counts["CRITICAL"] > 0:
        recs.append(
            f"<strong>Block deployments on {counts['CRITICAL']} critical finding(s).</strong> "
            "Add a CI gate: <code>depfence --fail-on critical</code>."
        )

    malicious = [f for f in findings if f.finding_type == FindingType.MALICIOUS]
    if malicious:
        pkgs = ", ".join(f"<code>{_h(f.package.name)}</code>" for f in malicious[:3])
        recs.append(
            f"<strong>Remove malicious package(s) immediately: {pkgs}.</strong> "
            "Treat the environment as potentially compromised."
        )

    typo = [f for f in findings if f.finding_type == FindingType.TYPOSQUAT]
    if typo:
        recs.append(
            f"<strong>Verify {len(typo)} possible typosquat(s).</strong> "
            "Check each package name against the intended dependency."
        )

    no_prov = [f for f in findings if f.finding_type == FindingType.PROVENANCE]
    if no_prov:
        recs.append(
            f"<strong>Enable provenance attestations.</strong> "
            f"{len(no_prov)} package(s) lack verified build provenance. "
            "Prefer packages with SLSA or Sigstore signatures."
        )

    if counts["MEDIUM"] + counts["HIGH"] > 10:
        recs.append(
            "<strong>Adopt continuous dependency monitoring.</strong> "
            "Run depfence on every pull request and block merges on new high/critical findings."
        )

    if not recs:
        recs.append(
            "<strong>No immediate action required.</strong> "
            "Continue running depfence on each release to maintain this security posture."
        )

    items = "\n".join(
        f'    <li class="rec-item">'
        f'<span class="rec-num">{i + 1}</span>'
        f'<span>{r}</span>'
        f'</li>'
        for i, r in enumerate(recs[:5])
    )
    return f"""
  <section class="report-section" id="section-recommendations">
    <h2 class="section-heading">Recommendations</h2>
    <ol class="rec-list">
{items}
    </ol>
  </section>"""


def _fix_suggestions(findings: list[Finding]) -> str:
    """Auto-fixable section retained for backward compatibility with existing tests."""
    fixable = [f for f in findings if f.fix_version]
    if not fixable:
        return ""
    rows = []
    for f in sorted(fixable, key=lambda x: _SEV_ORDER.get(x.severity.name.upper(), 9)):
        sev = f.severity.name.upper()
        pkg = _h(str(f.package))
        fix = _h(f.fix_version)
        title = _h(f.title)
        rows.append(
            f'    <tr>'
            f'<td>{_sev_badge(sev)}</td>'
            f'<td><code class="pkg-name">{pkg}</code></td>'
            f'<td>{title}</td>'
            f'<td><span class="fix-version">&#8594; {fix}</span></td>'
            f'</tr>'
        )
    return f"""
  <section class="report-section fix-section" id="section-autofixable">
    <h2 class="section-heading">Auto-fixable Vulnerabilities ({len(fixable)})</h2>
    <p class="section-desc">These packages have known safe versions available.</p>
    <div class="table-wrap">
      <table class="findings-table">
        <thead><tr>
          <th>Severity</th><th>Package</th><th>Finding</th><th>Fix Version</th>
        </tr></thead>
        <tbody>
{"".join(rows)}
        </tbody>
      </table>
    </div>
  </section>"""


# ---------------------------------------------------------------------------
# Stylesheet (light + dark via prefers-color-scheme)
# ---------------------------------------------------------------------------

_CSS = """
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:         #ffffff;
    --bg2:        #f6f8fa;
    --bg3:        #eaeef2;
    --border:     #d0d7de;
    --text:       #1f2328;
    --text-muted: #57606a;
    --accent:     #0969da;
    --font:       -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    --mono:       ui-monospace, SFMono-Regular, "SF Mono", Consolas, "Liberation Mono", monospace;
    --radius:     10px;
    --shadow:     0 1px 3px rgba(0,0,0,.08), 0 1px 2px rgba(0,0,0,.06);
  }

  @media (prefers-color-scheme: dark) {
    :root {
      --bg:         #0d1117;
      --bg2:        #161b22;
      --bg3:        #21262d;
      --border:     #30363d;
      --text:       #e6edf3;
      --text-muted: #8b949e;
      --accent:     #58a6ff;
      --shadow:     0 1px 3px rgba(0,0,0,.4), 0 1px 2px rgba(0,0,0,.3);
    }
  }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font);
    font-size: 14px;
    line-height: 1.6;
    min-height: 100vh;
  }

  .page-wrap {
    max-width: 1200px;
    margin: 0 auto;
    padding: 24px 16px 64px;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .report-section {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px 24px;
    box-shadow: var(--shadow);
  }
  .section-heading {
    font-size: 0.85rem;
    font-weight: 700;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 16px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--border);
  }
  .section-desc {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin-bottom: 12px;
    margin-top: -8px;
  }

  /* Header */
  .report-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 16px;
    padding: 24px;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
  }
  .depfence-brand {
    font-size: 0.7rem;
    color: var(--text-muted);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 4px;
  }
  .project-name {
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--text);
    margin-bottom: 6px;
    line-height: 1.2;
  }
  .header-meta {
    color: var(--text-muted);
    font-size: 0.84rem;
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 6px;
  }
  .header-meta .sep { opacity: 0.35; }
  .header-right {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 10px;
  }
  .grade-badge {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    width: 72px;
    height: 72px;
    border-radius: 50%;
    border: 3px solid;
    font-weight: 700;
  }
  .grade-letter { font-size: 2rem; line-height: 1; }
  .grade-label  { font-size: 0.58rem; text-transform: uppercase; letter-spacing: 0.08em; opacity: 0.8; }
  .status-pill {
    padding: 5px 16px;
    border-radius: 20px;
    border: 2px solid;
    font-size: 0.85rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    white-space: nowrap;
  }
  /* legacy compat */
  .status-badge {
    display: inline-block;
    padding: 5px 16px;
    border-radius: 20px;
    border: 2px solid transparent;
    font-size: 0.85rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    white-space: nowrap;
  }

  /* Summary Cards */
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 12px;
  }
  .card {
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 12px;
    text-align: center;
  }
  .card-value {
    font-size: 2rem;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 4px;
  }
  .card-label {
    font-size: 0.72rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }
  .card-critical .card-value { color: #ff4d4f; }
  .card-high     .card-value { color: #ff7a45; }
  .card-medium   .card-value { color: #ffc53d; }
  .card-low      .card-value { color: #52c41a; }
  .card-epss     .card-value { color: #eb2f96; }
  .card-kev      .card-value { color: #722ed1; }
  .card-total    .card-value { color: var(--text); }
  .card-pkgs     .card-value { color: var(--accent); }

  /* Bar Chart */
  .bar-chart { display: flex; flex-direction: column; gap: 10px; }
  .bar-row { display: flex; align-items: center; gap: 12px; }
  .bar-label {
    width: 72px;
    font-size: 0.78rem;
    font-weight: 600;
    text-align: right;
    color: var(--text-muted);
    flex-shrink: 0;
  }
  .bar-track {
    flex: 1;
    height: 16px;
    background: var(--bg3);
    border-radius: 8px;
    overflow: hidden;
  }
  .bar-fill { height: 100%; border-radius: 8px; min-width: 2px; }
  .bar-count { width: 36px; font-size: 0.82rem; font-weight: 700; text-align: right; flex-shrink: 0; }

  /* Filter Bar */
  .filter-bar {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
    padding: 12px 0;
    margin-bottom: 12px;
  }
  .filter-bar label { color: var(--text-muted); font-size: 0.82rem; }
  .filter-bar select,
  .filter-bar input {
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text);
    padding: 5px 10px;
    font-size: 0.85rem;
    font-family: var(--font);
    cursor: pointer;
  }
  .filter-bar input { flex: 1; min-width: 160px; }
  .filter-bar select:focus,
  .filter-bar input:focus { outline: none; border-color: var(--accent); }
  #filter-count { margin-left: auto; color: var(--text-muted); font-size: 0.82rem; }
  .btn-clear {
    background: transparent;
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text-muted);
    padding: 5px 12px;
    font-size: 0.82rem;
    cursor: pointer;
    font-family: var(--font);
  }
  .btn-clear:hover { border-color: var(--text-muted); color: var(--text); }

  /* Findings Table */
  .table-wrap { overflow-x: auto; }
  .findings-table {
    width: 100%;
    border-collapse: collapse;
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  .findings-table thead th {
    background: var(--bg3);
    color: var(--text-muted);
    font-size: 0.74rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    padding: 10px 12px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  .findings-table tbody tr {
    border-bottom: 1px solid var(--border);
    transition: background 0.1s;
  }
  .findings-table tbody tr:last-child { border-bottom: none; }
  .findings-table tbody tr:hover { background: var(--bg3); }
  .findings-table td { padding: 9px 12px; vertical-align: middle; font-size: 0.85rem; }
  .title-cell { max-width: 260px; word-break: break-word; }
  .detail-cell { color: var(--text-muted); max-width: 300px; word-break: break-word; }
  .no-findings {
    text-align: center;
    color: var(--text-muted);
    padding: 48px !important;
    font-size: 1rem;
  }
  .clean-icon { color: #52c41a; margin-right: 8px; }

  /* Badges */
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    white-space: nowrap;
    border: 1px solid transparent;
  }
  .eco-tag {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 0.68rem;
    font-weight: 600;
    background: var(--bg3);
    border: 1px solid var(--border);
    color: var(--text-muted);
    margin-left: 5px;
    vertical-align: middle;
  }
  .eco-npm   { border-color: #cb3837; color: #cb3837; }
  .eco-pypi  { border-color: #3776ab; color: #4fa3dc; }
  .eco-cargo { border-color: #ce422b; color: #e05b40; }
  .eco-go    { border-color: #00add8; color: #00cef0; }
  .eco-gha   { border-color: #2088ff; color: #4da3ff; }
  .eco-mcp   { border-color: #7c3aed; color: #a78bfa; }
  .cve-tag { font-family: var(--mono); font-size: 0.75rem; color: var(--accent); white-space: nowrap; }
  .none-dash { color: var(--text-muted); opacity: 0.35; }
  .fix-tag     { color: #52c41a; font-size: 0.82rem; white-space: nowrap; font-weight: 600; }
  .fix-version { color: #52c41a; font-weight: 600; }
  .type-tag    { font-size: 0.75rem; color: var(--text-muted); }
  code.pkg-name {
    font-family: var(--mono);
    font-size: 0.8rem;
    background: var(--bg3);
    padding: 1px 5px;
    border-radius: 4px;
    border: 1px solid var(--border);
    color: var(--accent);
    white-space: nowrap;
  }
  .epss-score { font-family: var(--mono); font-size: 0.8rem; padding: 1px 5px; border-radius: 4px; }
  .epss-high  { color: #ff4d4f; background: #3d0a0a; }
  .epss-med   { color: #ffc53d; background: #3d2900; }
  .health-badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    border: 1px solid;
    font-size: 0.78rem;
    font-weight: 700;
  }

  /* CSS-only donut chart */
  .donut-wrapper { display: flex; align-items: center; gap: 32px; flex-wrap: wrap; }
  .donut {
    width: 160px;
    height: 160px;
    border-radius: 50%;
    flex-shrink: 0;
    -webkit-mask: radial-gradient(circle at center, transparent 52px, black 53px);
    mask: radial-gradient(circle at center, transparent 52px, black 53px);
  }
  .donut-legend { display: flex; flex-direction: column; gap: 8px; flex: 1; min-width: 180px; }
  .legend-row { display: flex; align-items: center; gap: 10px; font-size: 0.85rem; }
  .legend-dot { width: 12px; height: 12px; border-radius: 3px; flex-shrink: 0; }
  .legend-label { flex: 1; color: var(--text); }
  .legend-count { color: var(--text-muted); font-weight: 600; min-width: 24px; text-align: right; }

  .fix-section { border-color: #2da44e; }

  /* Recommendations */
  .rec-list { list-style: none; display: flex; flex-direction: column; gap: 10px; }
  .rec-item {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 12px 14px;
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 8px;
    font-size: 0.88rem;
    line-height: 1.5;
  }
  .rec-num {
    width: 24px;
    height: 24px;
    border-radius: 50%;
    background: var(--accent);
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.72rem;
    font-weight: 700;
    flex-shrink: 0;
    margin-top: 1px;
  }

  /* Footer */
  .report-footer {
    text-align: center;
    color: var(--text-muted);
    font-size: 0.8rem;
    padding: 12px 0;
    border-top: 1px solid var(--border);
    margin-top: 8px;
  }
  .report-footer a { color: var(--accent); text-decoration: none; }

  @media (max-width: 700px) {
    .report-header { flex-direction: column; }
    .header-right  { flex-direction: row; align-items: center; }
    .summary-grid  { grid-template-columns: repeat(2, 1fr); }
    .donut-wrapper { flex-direction: column; align-items: flex-start; }
    .donut         { width: 120px; height: 120px; }
  }
"""

# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------

_JS = """
(function() {
  function applyFilters() {
    var sev   = document.getElementById('filter-sev');
    var eco   = document.getElementById('filter-eco');
    var query = document.getElementById('filter-search');
    if (!sev || !eco || !query) return;
    var sevVal   = sev.value;
    var ecoVal   = eco.value;
    var queryVal = query.value.toLowerCase();
    var rows     = document.querySelectorAll('#main-tbody tr[data-severity]');
    var shown    = 0;
    rows.forEach(function(row) {
      var ok = (sevVal === 'all' || row.getAttribute('data-severity') === sevVal)
            && (ecoVal === 'all' || row.getAttribute('data-ecosystem') === ecoVal)
            && (!queryVal || row.textContent.toLowerCase().indexOf(queryVal) !== -1);
      row.style.display = ok ? '' : 'none';
      if (ok) shown++;
    });
    var el = document.getElementById('filter-count');
    if (el && rows.length > 0) el.textContent = shown + ' of ' + rows.length + ' findings';
  }

  function clearFilters() {
    ['filter-sev','filter-eco'].forEach(function(id){
      var el = document.getElementById(id); if (el) el.value = 'all';
    });
    var q = document.getElementById('filter-search'); if (q) q.value = '';
    applyFilters();
  }

  window.applyFilters = applyFilters;
  window.clearFilters = clearFilters;
  applyFilters();
})();
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_html_report(
    result: ScanResult,
    project_name: str = "",
    enrichments: dict | None = None,
    extra_findings: list[Finding] | None = None,
) -> str:
    """Generate a self-contained HTML security report.

    Args:
        result:         The scan result containing findings.
        project_name:   Display name for the project (shown in the header).
        enrichments:    Optional dict with extra data. Supported keys:
                          - ``supply_chain_health``: list[dict] or dict with ``checks`` key.
                            Each check: {name, status (PASS|WARN|CRITICAL), detail}
                          - ``epss``: dict mapping CVE-ID -> float EPSS score
                          - ``kev``: list of CVE-IDs present in CISA KEV
        extra_findings: Additional findings to merge (backward-compat).

    Returns:
        A complete, self-contained HTML document string.
    """
    all_findings: list[Finding] = list(result.findings) + list(extra_findings or [])
    enrichments = enrichments or {}

    # Merge EPSS / KEV from enrichments into per-finding metadata
    epss_map: dict[str, float] = enrichments.get("epss", {}) or {}
    kev_set: set[str] = set(enrichments.get("kev", []) or [])

    enriched: list[Finding] = []
    for f in all_findings:
        if f.cve and (f.cve in epss_map or f.cve in kev_set):
            from dataclasses import replace as _dc_replace
            new_meta = dict(f.metadata)
            if f.cve in epss_map:
                new_meta["epss_score"] = epss_map[f.cve]
            if f.cve in kev_set:
                new_meta["in_kev"] = True
            enriched.append(_dc_replace(f, metadata=new_meta))
        else:
            enriched.append(f)
    all_findings = enriched

    counts = _count_by_severity(all_findings)
    status = _determine_status(all_findings)
    grade = _compute_grade(counts)
    total_findings = len(all_findings)
    packages_scanned = result.packages_scanned
    scan_date = (
        result.completed_at or result.started_at or datetime.now(tz=timezone.utc)
    ).strftime("%Y-%m-%d %H:%M UTC")

    sorted_findings = sorted(
        all_findings, key=lambda f: _SEV_ORDER.get(f.severity.name.upper(), 5)
    )

    epss_high_count = sum(
        1 for f in all_findings
        if isinstance(f.metadata.get("epss_score"), (int, float))
        and float(f.metadata["epss_score"]) >= 0.5
    )
    kev_count = sum(1 for f in all_findings if f.metadata.get("in_kev"))

    display_name = project_name or result.target

    sections = "\n".join([
        _build_header(display_name, scan_date, result.target, packages_scanned, grade, status),
        _build_executive_summary(counts, packages_scanned, total_findings, epss_high_count, kev_count),
        _build_severity_breakdown(counts),
        _fix_suggestions(all_findings),
        _build_findings_table(sorted_findings),
        _build_detection_categories(all_findings),
        _build_supply_chain_health(enrichments),
        _build_recommendations(all_findings),
        f"""  <footer class="report-footer">
    Generated by <strong>depfence v{__version__}</strong> at {_h(scan_date)}
    &nbsp;&middot;&nbsp;
    <a href="https://github.com/depfence/depfence">github.com/depfence/depfence</a>
  </footer>""",
    ])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>depfence Security Report &mdash; {_h(display_name)}</title>
<style>
{_CSS}
</style>
</head>
<body>
<div class="page-wrap">
{sections}
</div>
<script>
{_JS}
</script>
</body>
</html>"""
