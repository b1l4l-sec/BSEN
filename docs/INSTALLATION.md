# Installation

BSEN is a pure-Python CLI. Same steps on Windows and Linux.

## Requirements

- Python 3.9+
- `pip`

## Steps

```bash
git clone <this repo> BSEN
cd BSEN
python -m venv .venv

# Linux / macOS:
source .venv/bin/activate
# Windows (PowerShell):
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
pip install -e .
```

This installs the `bsen` console command. If you'd rather not install it,
every command also works as `python -m bsen.cli ...` from the project root.

## Optional extras

```bash
pip install paramiko   # required only for `bsen remote --os linux`
pip install pywinrm    # required only for `bsen remote --os windows`
```

## Windows notes

- Run from **Windows Terminal**, **PowerShell**, or `cmd.exe` — there is
  no separate desktop app to install.
- For full visibility (Defender/Firewall/BitLocker status, complete
  connection enumeration, autoruns registry keys under `HKLM`), run your
  terminal **as Administrator**.
- PowerShell's execution policy does not need to change — BSEN invokes
  `powershell -NoProfile -NonInteractive -Command "..."` directly, it
  does not execute `.ps1` script files.

## Linux notes

- Some checks (SUID/SGID sweep of `/`, full `/etc/sudoers.d` reads,
  reading other users' `authorized_keys`) are more complete when run
  with `sudo`, but BSEN degrades gracefully without it — permission
  errors are reported as INFO findings, not crashes.

## Verifying the install

```bash
bsen list-plugins
bsen scan --quick
```

You should see the BSEN banner, detected OS/version/architecture, and a
short scan with a security score.
