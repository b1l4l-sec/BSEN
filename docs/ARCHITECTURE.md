# BSEN Architecture

## Overview

BSEN is a single Python package (`bsen/`) run as a CLI — no client/server
split, no Electron shell, no database daemon. This keeps it a single
`pip install` on both Windows and Linux and lets it run headless in CI,
cron, or a scheduled task with zero extra services.

```
┌─────────────────────────────────────────────────────────┐
│                        bsen/cli.py                       │
│  argparse commands: scan | list-plugins | remote         │
│  Rich terminal UI (falls back to plain text if Rich       │
│  isn't installed — never a hard dependency for output)    │
└───────────────┬─────────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────────┐
│                bsen/core/plugin.py                        │
│  discover_plugins(): walks scanners/common, /windows,      │
│  /linux packages, imports every module, instantiates       │
│  every ScannerPlugin subclass whose platform matches        │
│  the host OS. This is the "auto-discovered at startup"     │
│  plugin system — adding a scanner never touches this file. │
└───────────────┬─────────────────────────────────────────┘
                │  ScannerPlugin.safe_scan() -> ScanResult
                ▼
┌─────────────────────────────────────────────────────────┐
│  scanners/common/*.py   (system, network, process)         │
│  scanners/windows/*.py  (security posture, autoruns)       │
│  scanners/linux/*.py    (security posture, persistence)    │
│  Each returns a ScanResult containing raw `data` plus a    │
│  list of normalized `Finding` objects.                     │
└───────────────┬─────────────────────────────────────────┘
                │  list[ScanResult]
                ▼
┌─────────────────────────────────────────────────────────┐
│  risk_engine/engine.py       -> RiskSummary (score/grade)  │
│  risk_engine/analyst.py      -> AnalystReport (rule-based  │
│                                  verdict, exec summary,     │
│                                  ranked findings, actions)  │
└───────────────┬─────────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────────┐
│  reporting/report_generator.py                             │
│  Builds one report dict, exports to JSON/Markdown/HTML/CSV │
└─────────────────────────────────────────────────────────┘
```

## Data model

`bsen/core/models.py` defines two dataclasses used by every plugin:

- **`Finding`** — one normalized issue: `category`, `title`, `severity`
  (INFO/LOW/MEDIUM/HIGH/CRITICAL), `description`, `evidence`,
  `recommendation`, `mitre_technique`, `risk_score`, `platform`,
  `source_plugin`.
- **`ScanResult`** — everything one plugin produced: raw `data` dict (for
  the JSON report / further tooling) plus `findings: list[Finding]`,
  timing, and an `error` field so one failing plugin never crashes the run
  (`safe_scan()` wraps every plugin in a try/except).

## Why no Electron/desktop app

Per project requirements, BSEN ships as a **terminal-only** tool: the same
`bsen` command works in Windows Terminal/PowerShell/cmd.exe and any Linux
shell, with no separate desktop runtime, no bundled Chromium, and no local
web server. This keeps the artifact small, scriptable, and trivially
deployable via cron/Task Scheduler/CI.

## Remote auditing model

`bsen/remote/remote_audit.py` implements credentialed remote assessment,
matching the trust model of Ansible/osquery/Wazuh: the operator supplies
credentials for a host they already administer.

- Linux targets: paramiko SSH + SFTP copies the package and runs the same
  local scan remotely, then pulls back `remote_report.json`.
- Windows targets: pywinrm runs a focused read-only PowerShell script
  in-memory over WinRM (no file transfer needed).

No unauthenticated scanning path exists anywhere in the codebase.

## Extending BSEN

See `PLUGIN_DEVELOPMENT.md`. In short: subclass `ScannerPlugin`, implement
`scan() -> ScanResult`, drop the file in the right `scanners/` subfolder.
