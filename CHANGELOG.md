# Changelog

## 1.0.0 — Terminal MVP

### Report & terminal display upgrade
- HTML/Markdown reports now include full **Machine Information** (host,
  user, OS, architecture, virtualization, CPU, RAM, uptime, storage) and
  a **Network** section with an actual **open/listening ports table**
  (local address, resolved service name, PID, sensitive-service flag),
  gateway/DNS, and connection counts — not just the findings list.
- HTML report restyled for a cleaner, more professional document look
  (structured section headers, bordered data tables, consistent spacing);
  no decorative icons or emoji anywhere in the report or CLI output.
- Terminal output now prints a **"Most Important Findings"** table
  directly after every scan — critical findings first, then top-ranked
  remaining findings, each with its recommendation — instead of only a
  severity count summary.
- Replaced the decorative bullet in the "Reports written" list with a
  plain dash for a more document-style, professional terminal output.

### Production-readiness pass (created by b1l4l-sec)
- Attribution: BSEN is created and maintained by **b1l4l-sec** — credited
  in the CLI banner, `--version`, and every generated report (JSON `meta.author`,
  Markdown/HTML footers).
- Added `pyproject.toml` alongside `setup.py` for modern packaging.
- Added `scripts/install.sh` (Linux/macOS) and `scripts/install.ps1`
  (Windows) one-command installers that create a venv, install the
  package, and verify with `bsen --version`.
- Added `.github/workflows/ci.yml`: matrix-tested on Ubuntu + Windows,
  Python 3.9/3.11/3.12, runs lint, unit tests, and a live smoke scan.
- Added `--version`, `--quiet`, and `--fail-on <SEVERITY>` flags for
  scripting, cron/Task Scheduler use, and CI/CD compliance gating,
  with defined exit codes (0/1/2).
- Fixed a bug where `--format` was accepted but silently ignored —
  report generation now honors the requested subset of formats.
- Plugin failures are now surfaced as a visible warning instead of
  silently vanishing into the report.
- Top-level exception handling so the CLI never stack-traces at the user.

### Added (functional MVP)
- Cross-platform CLI (`bsen scan`, `bsen list-plugins`, `bsen remote`) —
  Windows Terminal/PowerShell/cmd.exe and Linux shells, no desktop app.
- Auto-discovering plugin system (`bsen/core/plugin.py`).
- Priority 1 scanners: system, network, process, Windows security posture,
  Linux security posture, Windows autoruns/persistence, Linux
  persistence/forensics.
- Lightweight threat-hunting heuristics inside the process scanner
  (temp/AppData execution, encoded PowerShell / LOLBin abuse).
- Risk engine (0–100 score, A+–F grade) and rule-based AI Security Analyst.
- Report generation: JSON, Markdown, HTML (dark SOC-style theme), CSV.
- Credentialed remote auditing over SSH (Linux) and WinRM (Windows).
- Unit tests for models, risk engine, and plugin discovery (11/11 passing).

### Not yet implemented (see README Roadmap)
YARA matching, VirusTotal/AbuseIPDB/Shodan enrichment, Sigma mapping,
PE/ELF hash + signature validation, Windows Event Log analysis, WMI
persistence detection, COM/DLL/PATH hijacking checks, browser artifact
collection.
