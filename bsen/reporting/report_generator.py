"""
Report Generator
Builds the full scan report (machine info, score, findings, MITRE
mapping, analyst summary) and exports it as JSON / Markdown / HTML / CSV.

The HTML/Markdown reports surface the underlying scan data - not just
findings - so a reader gets a complete picture of the host: hardware,
OS, listening ports and services, and detailed findings with evidence.
"""
from __future__ import annotations

import csv
import json
import platform
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from bsen import __version__, __author__
from bsen.core.models import ScanResult
from bsen.risk_engine.analyst import AnalystReport
from bsen.risk_engine.engine import RiskSummary

BRAND_PRIMARY = "#00E5FF"
BRAND_SECONDARY = "#00FF88"
BRAND_BG = "#0D1117"
BRAND_PANEL = "#161B22"
BRAND_BORDER = "#30363D"
BRAND_TEXT = "#E6EDF3"
BRAND_TEXT_MUTED = "#8B949E"
BRAND_TEXT_DIM = "#6E7681"

RISKY_PORT_SERVICES = {
    21: "FTP", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS",
    445: "SMB", 3389: "RDP", 5900: "VNC",
}


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def build_report_dict(results: list[ScanResult], risk: RiskSummary, analyst: AnalystReport, scan_duration: float) -> dict:
    return {
        "meta": {
            "tool": "BSEN - Blue Security Endpoint Navigator",
            "author": __author__,
            "version": __version__,
            "generated_at": datetime.now().isoformat(),
            "platform": platform.system(),
            "platform_release": platform.release(),
            "hostname": platform.node(),
            "scan_duration_sec": round(scan_duration, 2),
        },
        "risk_summary": {
            "security_score": risk.security_score,
            "grade": risk.grade,
            "total_findings": risk.total_findings,
            "findings_by_severity": risk.findings_by_severity,
            "total_risk_score": risk.total_risk_score,
        },
        "analyst": {
            "verdict": analyst.verdict,
            "executive_summary": analyst.executive_summary,
            "critical_findings": analyst.critical_findings,
            "top_findings": analyst.top_findings,
            "recommended_actions": analyst.recommended_actions,
        },
        "scan_results": [r.to_dict() for r in results],
    }


def _scan_data(report: dict, plugin_name: str) -> dict:
    """Return the raw `data` dict from a specific plugin's scan result, or {} if absent."""
    for scan in report["scan_results"]:
        if scan["plugin_name"] == plugin_name:
            return scan.get("data") or {}
    return {}


def _fmt(value: Any, default: str = "n/a") -> str:
    if value is None or value == "":
        return default
    return str(value)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def write_json(report: dict, path: Path) -> None:
    path.write_text(json.dumps(report, indent=2, default=str))


# ---------------------------------------------------------------------------
# CSV (flat findings table - for spreadsheets / SIEM import)
# ---------------------------------------------------------------------------

def write_csv(report: dict, path: Path) -> None:
    rows = []
    for scan in report["scan_results"]:
        for f in scan["findings"]:
            rows.append(f)
    with open(path, "w", newline="") as fh:
        if not rows:
            fh.write("category,title,severity,description,evidence,recommendation,mitre_technique,risk_score\n")
            return
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def write_markdown(report: dict, path: Path) -> None:
    m = report["meta"]
    rs = report["risk_summary"]
    a = report["analyst"]
    sysd = _scan_data(report, "system_scanner")
    netd = _scan_data(report, "network_scanner")
    procd = _scan_data(report, "process_scanner")

    lines = [
        "# BSEN Security Assessment Report",
        "",
        f"| | |",
        f"|---|---|",
        f"| Host | {_fmt(m['hostname'])} |",
        f"| Platform | {_fmt(m['platform'])} {_fmt(m['platform_release'], '')} |",
        f"| Generated | {_fmt(m['generated_at'])} |",
        f"| Scan duration | {m['scan_duration_sec']}s |",
        f"| BSEN version | {m['version']} |",
        "",
        "## Executive Summary",
        "",
        f"**Verdict:** {a['verdict']}",
        "",
        a["executive_summary"],
        "",
        f"**Security Score:** {rs['security_score']}/100 (Grade {rs['grade']})  ",
        f"**Total Findings:** {rs['total_findings']}",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev, count in rs["findings_by_severity"].items():
        lines.append(f"| {sev} | {count} |")

    # --- Machine information -----------------------------------------
    if sysd:
        lines += ["", "## Machine Information", "", "| Property | Value |", "|---|---|"]
        rows = [
            ("Hostname", sysd.get("hostname")),
            ("Current user", sysd.get("current_user")),
            ("Operating system", f"{sysd.get('os_system','')} {sysd.get('os_release','')}"),
            ("Architecture", sysd.get("architecture")),
            ("Virtualization", sysd.get("virtualization")),
            ("CPU cores (logical/physical)", f"{sysd.get('cpu_logical_cores')} / {sysd.get('cpu_physical_cores')}"),
            ("CPU usage", f"{sysd.get('cpu_percent')}%" if sysd.get("cpu_percent") is not None else None),
            ("RAM total", f"{sysd.get('ram_total_gb')} GB" if sysd.get("ram_total_gb") is not None else None),
            ("RAM used", f"{sysd.get('ram_used_percent')}%" if sysd.get("ram_used_percent") is not None else None),
            ("Uptime", f"{sysd.get('uptime_hours')} hours" if sysd.get("uptime_hours") is not None else None),
            ("Boot time", sysd.get("boot_time")),
            ("Timezone", sysd.get("timezone")),
        ]
        for label, value in rows:
            lines.append(f"| {label} | {_fmt(value)} |")

        if sysd.get("disks"):
            lines += ["", "### Storage", "", "| Mount | Filesystem | Total (GB) | Used % |", "|---|---|---|---|"]
            for d in sysd["disks"]:
                lines.append(f"| {d.get('mountpoint')} | {d.get('fstype')} | {d.get('total_gb')} | {d.get('used_percent')}% |")

    # --- Network: open ports and services ------------------------------
    if netd:
        lines += ["", "## Network", "", "| Property | Value |", "|---|---|"]
        rows = [
            ("Local IP", netd.get("local_ip")),
            ("Gateway", netd.get("gateway")),
            ("DNS servers", ", ".join(netd.get("dns_servers") or []) or None),
            ("Listening ports", netd.get("listening_count")),
            ("Established connections", netd.get("established_count")),
        ]
        for label, value in rows:
            lines.append(f"| {label} | {_fmt(value)} |")

        listening = netd.get("listening_ports") or []
        if listening:
            lines += ["", "### Open / Listening Ports", "", "| Local Address | Service | PID | Flag |", "|---|---|---|---|"]
            for entry in listening:
                laddr = entry.get("laddr") or ""
                port = None
                if ":" in laddr:
                    try:
                        port = int(laddr.rsplit(":", 1)[1])
                    except ValueError:
                        port = None
                service = RISKY_PORT_SERVICES.get(port, "")
                flag = "SENSITIVE" if port in RISKY_PORT_SERVICES else ""
                lines.append(f"| {laddr} | {service} | {_fmt(entry.get('pid'))} | {flag} |")

    if procd:
        lines += ["", f"## Processes", "", f"Total running processes observed: **{procd.get('process_count', 'n/a')}**"]

    # --- Recommendations -------------------------------------------------
    lines += ["", "## Recommended Actions"]
    for rec in a["recommended_actions"]:
        lines.append(f"- {rec}")
    if not a["recommended_actions"]:
        lines.append("- No specific actions required at this time.")

    # --- Detailed findings -------------------------------------------------
    lines += ["", "## Detailed Findings"]
    any_findings = False
    for scan in report["scan_results"]:
        if not scan["findings"]:
            continue
        any_findings = True
        lines.append(f"### {scan['plugin_name']} ({scan['category']})")
        for f in scan["findings"]:
            lines.append(f"- **[{f['severity']}] {f['title']}**")
            lines.append(f"  - {f['description']}")
            if f.get("evidence"):
                lines.append(f"  - Evidence: `{f['evidence'][:300]}`")
            if f.get("mitre_technique"):
                lines.append(f"  - MITRE ATT&CK: `{f['mitre_technique']}`")
            if f.get("recommendation"):
                lines.append(f"  - Recommendation: {f['recommendation']}")
    if not any_findings:
        lines.append("No findings recorded - all checked controls passed.")

    lines.append("")
    lines.append("---")
    lines.append(f"Generated by BSEN - Blue Security Endpoint Navigator (read-only endpoint auditor), created by {__author__}. MIT License.")
    path.write_text("\n".join(lines))


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def write_html(report: dict, path: Path) -> None:
    m, rs, a = report["meta"], report["risk_summary"], report["analyst"]
    sysd = _scan_data(report, "system_scanner")
    netd = _scan_data(report, "network_scanner")
    procd = _scan_data(report, "process_scanner")

    sev_colors = {
        "CRITICAL": "#FF3B5C", "HIGH": "#FF8A00", "MEDIUM": "#FFD200",
        "LOW": "#00E5FF", "INFO": "#8B949E",
    }

    def sev_badge(sev: str) -> str:
        c = sev_colors.get(sev, BRAND_TEXT_MUTED)
        return (f'<span style="background:{c}22;color:{c};border:1px solid {c};'
                f'padding:2px 10px;border-radius:4px;font-size:11px;font-weight:700;'
                f'letter-spacing:0.5px;">{sev}</span>')

    def info_table(rows: list[tuple[str, Any]]) -> str:
        trs = "".join(
            f'<tr><td class="k">{label}</td><td class="v">{_fmt(value)}</td></tr>'
            for label, value in rows
        )
        return f'<table class="info-table">{trs}</table>'

    # --- Findings ---------------------------------------------------------
    findings_html = ""
    any_findings = False
    for scan in report["scan_results"]:
        if not scan["findings"]:
            continue
        any_findings = True
        findings_html += (
            f'<h3 class="section-sub">{scan["plugin_name"]} '
            f'<span class="muted">({scan["category"]})</span></h3>'
        )
        for f in scan["findings"]:
            evidence_html = (
                f'<p class="evidence">Evidence: <code>{f["evidence"][:300]}</code></p>'
                if f.get("evidence") else ""
            )
            mitre_html = (
                f'<p class="meta-line">MITRE ATT&amp;CK: <code>{f["mitre_technique"]}</code></p>'
                if f.get("mitre_technique") else ""
            )
            rec_html = (
                f'<p class="recommendation">Recommendation: {f["recommendation"]}</p>'
                if f.get("recommendation") else ""
            )
            findings_html += f"""
            <div class="finding-card">
              <div class="finding-head">
                <strong>{f['title']}</strong>
                {sev_badge(f['severity'])}
              </div>
              <p class="finding-desc">{f['description']}</p>
              {evidence_html}
              {mitre_html}
              {rec_html}
            </div>
            """
    if not any_findings:
        findings_html = '<p class="muted">No findings recorded - all checked controls passed.</p>'

    # --- Severity summary table --------------------------------------------
    sev_rows = "".join(
        f'<tr><td class="k">{sev}</td><td class="v">{count}</td></tr>'
        for sev, count in rs["findings_by_severity"].items() if count
    )
    if not sev_rows:
        sev_rows = '<tr><td class="k">-</td><td class="v">No findings</td></tr>'

    recs_html = "".join(f"<li>{r}</li>" for r in a["recommended_actions"])
    if not recs_html:
        recs_html = "<li>No specific actions required at this time.</li>"

    # --- Machine information section --------------------------------------
    machine_html = ""
    if sysd:
        machine_rows = [
            ("Hostname", sysd.get("hostname")),
            ("Current user", sysd.get("current_user")),
            ("Operating system", f"{sysd.get('os_system','')} {sysd.get('os_release','')}".strip()),
            ("Architecture", sysd.get("architecture")),
            ("Virtualization", sysd.get("virtualization")),
            ("CPU cores (logical/physical)", f"{sysd.get('cpu_logical_cores')} / {sysd.get('cpu_physical_cores')}"),
            ("CPU usage", f"{sysd.get('cpu_percent')}%" if sysd.get("cpu_percent") is not None else None),
            ("RAM total", f"{sysd.get('ram_total_gb')} GB" if sysd.get("ram_total_gb") is not None else None),
            ("RAM used", f"{sysd.get('ram_used_percent')}%" if sysd.get("ram_used_percent") is not None else None),
            ("Uptime", f"{sysd.get('uptime_hours')} hours" if sysd.get("uptime_hours") is not None else None),
            ("Boot time", sysd.get("boot_time")),
            ("Timezone", sysd.get("timezone")),
        ]
        disks_html = ""
        if sysd.get("disks"):
            disk_rows = "".join(
                f'<tr><td class="k">{d.get("mountpoint")}</td><td class="v">{d.get("fstype")}</td>'
                f'<td class="v">{d.get("total_gb")} GB</td><td class="v">{d.get("used_percent")}%</td></tr>'
                for d in sysd["disks"]
            )
            disks_html = f"""
            <h3 class="section-sub">Storage</h3>
            <table class="data-table">
              <thead><tr><th>Mount</th><th>Filesystem</th><th>Total</th><th>Used</th></tr></thead>
              <tbody>{disk_rows}</tbody>
            </table>
            """
        machine_html = f"""
        <h2 class="section-title">Machine Information</h2>
        {info_table(machine_rows)}
        {disks_html}
        """

    # --- Network / open ports section --------------------------------------
    network_html = ""
    if netd:
        network_rows = [
            ("Local IP", netd.get("local_ip")),
            ("Gateway", netd.get("gateway")),
            ("DNS servers", ", ".join(netd.get("dns_servers") or []) or None),
            ("Listening ports", netd.get("listening_count")),
            ("Established connections", netd.get("established_count")),
        ]
        listening = netd.get("listening_ports") or []
        ports_html = ""
        if listening:
            port_rows = ""
            for entry in listening:
                laddr = entry.get("laddr") or ""
                port = None
                if ":" in laddr:
                    try:
                        port = int(laddr.rsplit(":", 1)[1])
                    except ValueError:
                        port = None
                service = RISKY_PORT_SERVICES.get(port, "-")
                flag = (
                    '<span class="flag-sensitive">SENSITIVE</span>' if port in RISKY_PORT_SERVICES
                    else '<span class="muted">-</span>'
                )
                port_rows += (
                    f'<tr><td class="v">{laddr}</td><td class="v">{service}</td>'
                    f'<td class="v">{_fmt(entry.get("pid"))}</td><td>{flag}</td></tr>'
                )
            ports_html = f"""
            <h3 class="section-sub">Open / Listening Ports</h3>
            <table class="data-table">
              <thead><tr><th>Local Address</th><th>Service</th><th>PID</th><th>Flag</th></tr></thead>
              <tbody>{port_rows}</tbody>
            </table>
            """
        else:
            ports_html = '<p class="muted">No listening ports were recorded.</p>'

        network_html = f"""
        <h2 class="section-title">Network</h2>
        {info_table(network_rows)}
        {ports_html}
        """

    processes_html = ""
    if procd:
        processes_html = f"""
        <h2 class="section-title">Processes</h2>
        <p>Total running processes observed: <strong>{_fmt(procd.get('process_count'))}</strong></p>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>BSEN Security Report - {m['hostname']}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    background:{BRAND_BG}; color:{BRAND_TEXT};
    font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    margin:0; padding:48px 24px;
  }}
  .container {{ max-width: 980px; margin: 0 auto; }}
  .header {{
    display:flex; justify-content:space-between; align-items:flex-start;
    border-bottom:1px solid {BRAND_BORDER}; padding-bottom:24px; margin-bottom:32px;
  }}
  .logo {{ font-size:26px; font-weight:800; color:{BRAND_PRIMARY}; letter-spacing:3px; }}
  .tagline {{ color:{BRAND_TEXT_MUTED}; font-size:13px; margin-top:4px; }}
  .header-meta {{ text-align:right; color:{BRAND_TEXT_MUTED}; font-size:13px; line-height:1.6; }}

  .score-card {{
    background: linear-gradient(135deg, {BRAND_PANEL}, #1a2029);
    border:1px solid {BRAND_BORDER}; border-radius:12px; padding:28px 32px;
    display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;
  }}
  .score-label {{ color:{BRAND_TEXT_MUTED}; font-size:12px; text-transform:uppercase; letter-spacing:1.5px; margin-bottom:6px; }}
  .score-num {{ font-size:48px; font-weight:800; color:{BRAND_SECONDARY}; line-height:1; }}
  .score-num span {{ font-size:20px; color:{BRAND_TEXT_MUTED}; font-weight:400; }}
  .grade {{ font-size:30px; font-weight:800; color:{BRAND_PRIMARY}; }}
  .verdict-text {{ font-size:15px; font-weight:600; color:{BRAND_SECONDARY}; max-width:280px; text-align:right; }}

  .section-title {{ color:{BRAND_PRIMARY}; font-size:20px; font-weight:700; margin-top:40px; margin-bottom:14px;
    border-bottom:1px solid {BRAND_BORDER}; padding-bottom:8px; }}
  .section-sub {{ color:{BRAND_TEXT}; font-size:16px; font-weight:700; margin-top:24px; margin-bottom:10px; }}
  .muted {{ color:{BRAND_TEXT_MUTED}; }}

  p {{ line-height:1.65; color:#B8C0C8; }}

  table {{ border-collapse: collapse; width:100%; margin-bottom:8px; }}
  .info-table td {{ padding:7px 14px; border-bottom:1px solid {BRAND_BORDER}; font-size:14px; }}
  .info-table td.k {{ color:{BRAND_TEXT_MUTED}; width:38%; }}
  .info-table td.v {{ color:{BRAND_TEXT}; font-weight:500; }}

  .data-table {{ border:1px solid {BRAND_BORDER}; border-radius:8px; overflow:hidden; }}
  .data-table thead th {{
    background:{BRAND_PANEL}; color:{BRAND_TEXT_MUTED}; text-align:left; padding:9px 14px;
    font-size:11px; text-transform:uppercase; letter-spacing:0.6px; border-bottom:1px solid {BRAND_BORDER};
  }}
  .data-table tbody td {{ padding:9px 14px; font-size:13px; border-bottom:1px solid {BRAND_BORDER}; color:{BRAND_TEXT}; }}
  .data-table tbody tr:last-child td {{ border-bottom:none; }}
  .flag-sensitive {{
    color:#FF8A00; font-size:11px; font-weight:700; border:1px solid #FF8A00;
    padding:2px 8px; border-radius:4px; background:#FF8A0022;
  }}

  code {{ background:#0d1117; padding:2px 6px; border-radius:4px; color:{BRAND_PRIMARY}; font-size:12px; }}

  ul {{ padding-left:20px; }}
  li {{ margin-bottom:7px; color:#B8C0C8; line-height:1.5; }}

  .finding-card {{
    background:{BRAND_PANEL}; border:1px solid {BRAND_BORDER}; border-left:3px solid {BRAND_PRIMARY};
    border-radius:8px; padding:16px 20px; margin-bottom:12px;
  }}
  .finding-head {{ display:flex; justify-content:space-between; align-items:center; gap:12px; }}
  .finding-head strong {{ color:{BRAND_TEXT}; font-size:15px; }}
  .finding-desc {{ margin:8px 0 4px 0; font-size:14px; }}
  .evidence {{ font-size:12px; color:{BRAND_TEXT_MUTED}; margin:4px 0; }}
  .meta-line {{ font-size:12px; color:{BRAND_TEXT_MUTED}; margin:4px 0; }}
  .recommendation {{ font-size:13px; color:{BRAND_SECONDARY}; margin:6px 0 0 0; }}

  .footer {{
    margin-top:56px; color:{BRAND_TEXT_DIM}; font-size:12px;
    border-top:1px solid {BRAND_BORDER}; padding-top:18px; line-height:1.6;
  }}
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <div>
      <div class="logo">BSEN</div>
      <div class="tagline">Blue Security Endpoint Navigator &mdash; Endpoint Security Audit Report</div>
      <div class="tagline">Created by {m['author']}</div>
    </div>
    <div class="header-meta">
      {m['hostname']}<br>{m['platform']} {m['platform_release']}<br>{m['generated_at']}
    </div>
  </div>

  <div class="score-card">
    <div>
      <div class="score-label">Security Score</div>
      <div class="score-num">{rs['security_score']}<span>/100</span></div>
    </div>
    <div style="text-align:center;">
      <div class="score-label">Grade</div>
      <div class="grade">{rs['grade']}</div>
    </div>
    <div>
      <div class="score-label" style="text-align:right;">Verdict</div>
      <div class="verdict-text">{a['verdict']}</div>
    </div>
  </div>

  <h2 class="section-title">Executive Summary</h2>
  <p>{a['executive_summary']}</p>
  <table class="info-table">{sev_rows}</table>

  {machine_html}

  {network_html}

  {processes_html}

  <h2 class="section-title">Recommended Actions</h2>
  <ul>{recs_html}</ul>

  <h2 class="section-title">Detailed Findings</h2>
  {findings_html}

  <div class="footer">
    Generated by BSEN v{m['version']} &middot; Created by {m['author']} &middot; Scan duration {m['scan_duration_sec']}s<br>
    MIT License &middot; Read-only defensive audit tool - not an antivirus.
  </div>
</div>
</body>
</html>"""
    path.write_text(html)


# ---------------------------------------------------------------------------
# Format dispatch
# ---------------------------------------------------------------------------

_FORMAT_ALIASES = {"md": "markdown", "markdown": "markdown", "json": "json", "html": "html", "csv": "csv"}
_WRITERS = {"json": write_json, "markdown": write_markdown, "html": write_html, "csv": write_csv}
_EXTENSIONS = {"json": "json", "markdown": "md", "html": "html", "csv": "csv"}


def generate_all_formats(report: dict, output_dir: Path, basename: str,
                          formats: Optional[list[str]] = None) -> dict[str, Path]:
    """Write the requested report formats. `formats` accepts any of
    json/md/markdown/html/csv (case-insensitive); defaults to all four."""
    output_dir.mkdir(parents=True, exist_ok=True)

    if formats:
        requested = []
        for f in formats:
            key = _FORMAT_ALIASES.get(f.strip().lower())
            if key and key not in requested:
                requested.append(key)
    else:
        requested = ["json", "markdown", "html", "csv"]

    paths: dict[str, Path] = {}
    for fmt in requested:
        path = output_dir / f"{basename}.{_EXTENSIONS[fmt]}"
        _WRITERS[fmt](report, path)
        paths[fmt] = path
    return paths
