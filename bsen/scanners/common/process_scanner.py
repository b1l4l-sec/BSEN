"""
Process Scanner (Priority 1) + light Threat Hunting heuristics (Priority 2).
Enumerates running processes, flags common LOLBin/suspicious-execution patterns.
Read-only: only inspects process metadata, never touches process memory or state.
"""
from __future__ import annotations

import os

import psutil

from bsen.core.models import Finding, ScanResult, Severity, now
from bsen.core.plugin import ScannerPlugin

SUSPICIOUS_PATH_FRAGMENTS = ["\\temp\\", "/tmp/", "\\appdata\\local\\temp", "/dev/shm/"]
LOLBINS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "certutil.exe", "regsvr32.exe", "rundll32.exe", "bitsadmin.exe",
    "curl", "wget", "nc", "ncat", "python", "python3", "bash",
}
ENCODED_FLAGS = ["-enc", "-encodedcommand", "-e ", "frombase64string", "iex(", "invoke-expression"]


class ProcessScanner(ScannerPlugin):
    name = "process_scanner"
    category = "threat_hunting"
    platform_supported = "any"
    priority = 1

    def scan(self) -> ScanResult:
        started = now()
        findings: list[Finding] = []
        processes = []

        for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]):
            try:
                info = p.info
                cmdline = " ".join(info.get("cmdline") or [])
                exe = info.get("exe") or ""
                name = (info.get("name") or "").lower()

                entry = {
                    "pid": info.get("pid"),
                    "ppid": info.get("ppid"),
                    "name": info.get("name"),
                    "exe": exe,
                    "cmdline": cmdline,
                    "username": info.get("username"),
                }
                processes.append(entry)

                exe_lower = exe.lower()
                if any(frag in exe_lower for frag in SUSPICIOUS_PATH_FRAGMENTS) or \
                   any(frag in cmdline.lower() for frag in SUSPICIOUS_PATH_FRAGMENTS):
                    findings.append(Finding(
                        category="threat_hunting",
                        title="Process executing from a temp/appdata location",
                        severity=Severity.MEDIUM,
                        description=f"Process '{info.get('name')}' (PID {info.get('pid')}) is running from a "
                                    f"temporary or user-writable directory, a common malware staging pattern.",
                        evidence=f"exe={exe} cmdline={cmdline[:200]}",
                        recommendation="Verify the binary's legitimacy and origin. Consider hash lookup / signature check.",
                        mitre_technique="T1036 / T1574",
                        platform="any",
                        source_plugin=self.name,
                    ))

                cmd_lower = cmdline.lower()
                if name in LOLBINS and any(flag in cmd_lower for flag in ENCODED_FLAGS):
                    findings.append(Finding(
                        category="threat_hunting",
                        title="Encoded/obfuscated command-line execution detected",
                        severity=Severity.HIGH,
                        description=f"'{info.get('name')}' (PID {info.get('pid')}) was launched with an "
                                     f"encoded or dynamically-evaluated command, a common evasion technique.",
                        evidence=f"cmdline={cmdline[:200]}",
                        recommendation="Investigate the parent process and command history immediately.",
                        mitre_technique="T1027 / T1059",
                        platform="any",
                        source_plugin=self.name,
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        data = {
            "process_count": len(processes),
            "processes": processes[:500],  # cap
        }

        return ScanResult(
            plugin_name=self.name,
            category=self.category,
            platform=self.platform_supported,
            started_at=started,
            finished_at=now(),
            data=data,
            findings=findings,
        )
