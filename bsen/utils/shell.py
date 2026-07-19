"""
Read-only command execution helper.

Every scanner that needs to shell out to a system tool (systemctl,
netstat, reg query, sc query, etc.) goes through here so there is a
single audited chokepoint. No scanner is permitted to run a command
that modifies system state - this helper is intentionally simple and
does not attempt to sanitize write/exploit commands because none
should ever be passed to it in the first place (enforced by code
review of the scanners themselves, not by this function).
"""
from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class CommandResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: Optional[int]


def run(cmd: str | list[str], timeout: int = 15) -> CommandResult:
    """Run a read-only shell command and capture output. Never raises."""
    try:
        if isinstance(cmd, str):
            args = shlex.split(cmd, posix=(subprocess.os.name != "nt"))
        else:
            args = cmd
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return CommandResult(
            ok=proc.returncode == 0,
            stdout=proc.stdout.strip(),
            stderr=proc.stderr.strip(),
            returncode=proc.returncode,
        )
    except FileNotFoundError:
        return CommandResult(ok=False, stdout="", stderr="command not found", returncode=None)
    except subprocess.TimeoutExpired:
        return CommandResult(ok=False, stdout="", stderr="timed out", returncode=None)
    except Exception as exc:  # noqa: BLE001
        return CommandResult(ok=False, stdout="", stderr=str(exc), returncode=None)
