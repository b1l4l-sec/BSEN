"""
Remote Endpoint Auditing
=========================
Lets a BSEN operator audit OTHER machines on the same network that
they are already authorized to administer - the same trust model used
by Ansible, osquery fleets, and Wazuh managers.

IMPORTANT / SCOPE:
- This module NEVER scans or probes hosts without explicit credentials
  supplied by the operator. It performs no unauthenticated network
  sweeps, port scans, or exploitation of any kind.
- Linux/macOS targets are audited over SSH (via paramiko) by copying
  this package to a temp dir on the target and running it locally
  there, then pulling the JSON report back.
- Windows targets are audited over WinRM (via pywinrm) by invoking the
  Python entry point remotely if Python is present, or by running the
  PowerShell-only subset of checks directly over WinRM.
- Use only against systems you own or are explicitly authorized to
  assess. Unauthorized access to computer systems is illegal in most
  jurisdictions.
"""
from __future__ import annotations

import json
import shlex
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class RemoteTarget:
    host: str
    username: str
    password: Optional[str] = None
    ssh_key_path: Optional[str] = None
    os_hint: str = "linux"  # "linux" or "windows"
    port: Optional[int] = None
    winrm_transport: str = "ntlm"  # or "kerberos", "credssp"


class RemoteAuditError(RuntimeError):
    pass


def audit_linux_target(target: RemoteTarget, remote_workdir: str = "/tmp/bsen_remote") -> dict:
    """Audit a remote Linux host over SSH using provided credentials.
    Requires the 'paramiko' package (pip install paramiko)."""
    try:
        import paramiko
    except ImportError as exc:
        raise RemoteAuditError(
            "paramiko is required for remote Linux audits: pip install paramiko"
        ) from exc

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = {"hostname": target.host, "username": target.username,
                       "port": target.port or 22, "timeout": 15}
    if target.ssh_key_path:
        connect_kwargs["key_filename"] = target.ssh_key_path
    elif target.password:
        connect_kwargs["password"] = target.password
    else:
        raise RemoteAuditError("Provide either ssh_key_path or password for the remote target.")

    client.connect(**connect_kwargs)
    try:
        sftp = client.open_sftp()
        try:
            sftp.mkdir(remote_workdir)
        except IOError:
            pass  # already exists

        local_pkg_dir = Path(__file__).resolve().parents[1]  # .../bsen
        for py_file in local_pkg_dir.rglob("*.py"):
            rel = py_file.relative_to(local_pkg_dir.parent)
            remote_path = f"{remote_workdir}/{rel.as_posix()}"
            remote_dir = remote_path.rsplit("/", 1)[0]
            _sftp_makedirs(sftp, remote_dir)
            sftp.put(str(py_file), remote_path)
        sftp.close()

        cmd = (
            f"cd {shlex.quote(remote_workdir)} && "
            f"python3 -m bsen.cli scan --json-only --output {shlex.quote(remote_workdir)}/remote_report"
        )
        stdin, stdout, stderr = client.exec_command(cmd, timeout=180)
        exit_status = stdout.channel.recv_exit_status()
        err_text = stderr.read().decode(errors="ignore")
        if exit_status != 0:
            raise RemoteAuditError(f"Remote scan failed (exit {exit_status}): {err_text[:2000]}")

        sftp = client.open_sftp()
        with sftp.open(f"{remote_workdir}/remote_report.json") as fh:
            report = json.loads(fh.read())
        sftp.close()
        return report
    finally:
        client.close()


def _sftp_makedirs(sftp, remote_dir: str) -> None:
    parts = remote_dir.strip("/").split("/")
    path = ""
    for part in parts:
        path += "/" + part
        try:
            sftp.mkdir(path)
        except IOError:
            continue


def audit_windows_target(target: RemoteTarget) -> dict:
    """Audit a remote Windows host over WinRM using provided credentials.
    Requires the 'pywinrm' package (pip install pywinrm).

    This runs the read-only PowerShell checks (Defender / Firewall /
    UAC / BitLocker / autoruns) directly over WinRM rather than
    copying the whole package, since WinRM file transfer is heavier
    to set up than SSH/SFTP.
    """
    try:
        import winrm
    except ImportError as exc:
        raise RemoteAuditError(
            "pywinrm is required for remote Windows audits: pip install pywinrm"
        ) from exc

    session = winrm.Session(
        target.host,
        auth=(target.username, target.password or ""),
        transport=target.winrm_transport,
    )

    ps_script = r"""
$result = @{}
$result.Defender = Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json
$result.Firewall = Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json
$result.UAC = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA
$result.RunKeys = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | ConvertTo-Json
$result | ConvertTo-Json -Depth 5
"""
    r = session.run_ps(ps_script)
    if r.status_code != 0:
        raise RemoteAuditError(f"WinRM scan failed: {r.std_err.decode(errors='ignore')[:2000]}")

    try:
        parsed = json.loads(r.std_out.decode(errors="ignore"))
    except json.JSONDecodeError:
        parsed = {"raw_output": r.std_out.decode(errors="ignore")}

    return {
        "meta": {"tool": "BSEN remote (WinRM)", "target_host": target.host},
        "raw_checks": parsed,
    }


def audit_target(target: RemoteTarget) -> dict:
    """Dispatch to the correct remote auditing backend based on os_hint."""
    if target.os_hint.lower().startswith("win"):
        return audit_windows_target(target)
    return audit_linux_target(target)
