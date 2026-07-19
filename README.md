# BSEN <=> Blue Security Endpoint Navigator

**Professional cross-platform endpoint security auditor & digital forensics CLI.**
*Created by [b1l4l-sec](https://github.com/b1l4l-sec).*

BSEN is a **read-only** defensive auditing tool for Windows and Linux endpoints,
in the spirit of Sysinternals Autoruns, WinPEAS/LinPEAS, Lynis, and osquery.
It is **not** an antivirus and **never** exploits, modifies, or attacks anything —
every check is a query, never a write.

Runs entirely in your terminal — **Windows Terminal / PowerShell / cmd.exe on
Windows, and any shell on Linux.** There is no desktop/Electron app; BSEN is a
pure Python CLI so it's lightweight, scriptable, and CI/cron-friendly on both
platforms.

```
██████╗ ███████╗███████╗███╗   ██╗
██╔══██╗██╔════╝██╔════╝████╗  ██║
██████╔╝███████╗█████╗  ██╔██╗ ██║
██╔══██╗╚════██║██╔══╝  ██║╚██╗██║
██████╔╝███████║███████╗██║ ╚████║
╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝
 Blue Security Endpoint Navigator
```

## What it does

On startup BSEN auto-detects your OS (Windows or Linux), version, and
architecture, then loads the matching scanner plugins automatically — you
never have to tell it what platform you're on.

| Module | Windows | Linux |
|---|---|---|
| System info (host, CPU, RAM, disk, uptime, VM detection) | ✅ | ✅ |
| Network (interfaces, listening ports, connections, gateway/DNS) | ✅ | ✅ |
| Process & lightweight threat-hunting heuristics | ✅ | ✅ |
| Security posture (Defender, Firewall, BitLocker, Secure Boot, UAC) | ✅ | — |
| Security posture (ufw/firewalld, SELinux/AppArmor, auditd, SSH hardening) | — | ✅ |
| Autoruns / persistence (Run keys, scheduled tasks, services) | ✅ | — |
| Persistence / forensics (cron, systemd, sudoers, SUID/SGID, authorized_keys) | — | ✅ |
| Risk engine (0–100 score, A+–F grade) | ✅ | ✅ |
| Rule-based AI Security Analyst (verdict, exec summary, actions) | ✅ | ✅ |
| Reports: JSON / Markdown / HTML / CSV | ✅ | ✅ |
| Remote credentialed audit (SSH / WinRM) | ✅ | ✅ |

Every finding is normalized to: **category, severity, description, evidence,
recommendation, MITRE ATT&CK technique, risk score, platform**.

## Install

**One-liner (recommended):**

```bash
git clone <this repo> BSEN && cd BSEN

# Linux / macOS
./scripts/install.sh

# Windows (PowerShell — run: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned  once, if blocked)
.\scripts\install.ps1
```

This creates a virtual environment, installs BSEN, and verifies the install
by printing `bsen --version`.

**Manual install:**

```bash
git clone <this repo> BSEN && cd BSEN
pip install -r requirements.txt
pip install -e .          # gives you the `bsen` command; or use `python -m bsen.cli`
```

Requires Python 3.9+. Works identically via `python -m bsen.cli ...` if you
don't want to install the console script.

## Usage

```bash
# Full audit of the local machine, all report formats
bsen scan

# Quick scan (system + network only, fast)
bsen scan --quick

# Choose specific report formats
bsen scan --format json,html

# Custom output directory
bsen scan --output ./my_reports

# Suppress banner/summary (reports are still written) - good for cron/Task Scheduler
bsen scan --quiet

# CI/CD & compliance gating: exit non-zero if any HIGH or CRITICAL finding exists
bsen scan --fail-on HIGH

# List every auto-discovered scanner plugin
bsen list-plugins

# Show installed version
bsen --version

# Audit ANOTHER machine on your network that you're authorized to manage
bsen remote --host 10.0.0.15 --user admin --os linux --ssh-key ~/.ssh/id_rsa
bsen remote --host 10.0.0.20 --user Administrator --os windows --password '***'
```

**Exit codes** (for scripting/CI/scheduled tasks): `0` clean run, no
`--fail-on` breach · `1` a finding at/above the `--fail-on` threshold was
found · `2` a runtime error occurred.

On Windows, run these same commands from **Windows Terminal, PowerShell, or
cmd.exe** — no separate app is needed. Some checks (Defender/Firewall/BitLocker
status, full connection enumeration) benefit from running as Administrator.

## Reports

Every scan writes a timestamped report set to `reports/` by default:

- `bsen_report_<host>_<ts>.json` — full machine-readable output
- `bsen_report_<host>_<ts>.md` — human-readable Markdown summary
- `bsen_report_<host>_<ts>.html` — styled dark-theme SOC-style report
- `bsen_report_<host>_<ts>.csv` — flat findings table for spreadsheets/SIEM import

Each report includes: executive summary, security score & grade, findings by
severity, an AI Security Analyst verdict and recommended actions, and full
per-plugin evidence with MITRE ATT&CK mapping.

## Remote auditing (same-network endpoints)

`bsen remote` lets an operator assess **other machines they already
administer** — the same trust model as Ansible, osquery fleets, or a Wazuh
manager:

- **Linux targets** are audited over **SSH** (`pip install paramiko`): BSEN
  copies itself to the target, runs the same read-only scan locally there,
  and pulls the JSON report back over SFTP.
- **Windows targets** are audited over **WinRM** (`pip install pywinrm`):
  the read-only PowerShell checks (Defender/Firewall/UAC/BitLocker/autoruns)
  run directly on the target via WinRM.

Credentials are **always required** — BSEN performs no unauthenticated
scanning, port probing, or exploitation of any host. Only use this against
systems you own or are explicitly authorized to assess; unauthorized access
to computer systems is illegal in most jurisdictions.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design, and
[docs/PLUGIN_DEVELOPMENT.md](docs/PLUGIN_DEVELOPMENT.md) to add your own
scanner in a few lines of code.

```
bsen/
  cli.py                 CLI entry point (Rich terminal UI, falls back to plain text)
  core/                  Finding/ScanResult models + plugin base class & auto-discovery
  scanners/
    common/               cross-platform: system, network, process/threat-hunting
    windows/               Windows-only: security posture, autoruns/persistence
    linux/                 Linux-only: security posture, persistence/forensics
  risk_engine/            scoring engine + rule-based AI Security Analyst
  reporting/              JSON/Markdown/HTML/CSV report generation
  remote/                 credentialed SSH/WinRM remote auditing
```

## Roadmap (Priority 2/3 items not yet in this MVP)

YARA rule matching, VirusTotal/AbuseIPDB enrichment, Sigma rule mapping,
digital signature/hash validation (PE/ELF metadata), browser artifact
collection, Windows Event Log analysis (failed/privileged logons), WMI
persistence detection (event consumers/filters/bindings), COM/DLL/PATH
hijacking checks. The plugin system (see below) makes each of these a
self-contained addition — no core changes required.

## Plugin system

Every scanner is a plugin: a class inheriting `ScannerPlugin` in
`bsen/scanners/{common,windows,linux}/`. Plugins are **auto-discovered at
startup** by walking those packages — drop in a new file, and it's picked
up automatically, no registration step, no core edits. See
`docs/PLUGIN_DEVELOPMENT.md`.

## Security & ethics

- 100% read-only: no scanner writes to the registry, filesystem, or system
  configuration, and none disables/enables/modifies services.
- No exploitation code of any kind — this project detects risk, it never
  creates it.
- Remote auditing requires credentials you already possess for systems you
  administer; there is no unauthenticated scanning capability.

## License

MIT — see [LICENSE](LICENSE).

---

**BSEN** is created and maintained by **b1l4l-sec**.
