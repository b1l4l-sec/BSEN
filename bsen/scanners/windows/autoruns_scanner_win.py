"""
Windows Autoruns / Persistence Scanner (Priority 1/2)
Registry Run keys, scheduled tasks, services - the classic Autoruns
categories reimplemented as read-only registry/WMI queries.
"""
from __future__ import annotations

from bsen.core.models import Finding, ScanResult, Severity, now
from bsen.core.plugin import ScannerPlugin
from bsen.utils.shell import run

RUN_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
]


class WindowsAutorunsScanner(ScannerPlugin):
    name = "windows_autoruns_scanner"
    category = "forensics"
    platform_supported = "windows"
    priority = 1

    def scan(self) -> ScanResult:
        started = now()
        findings: list[Finding] = []
        data = {"run_keys": {}, "scheduled_tasks": None, "services": None}

        for key in RUN_KEYS:
            res = run(["reg", "query", key])
            data["run_keys"][key] = res.stdout if res.ok else None
            if res.ok and res.stdout:
                entries = [l for l in res.stdout.splitlines() if l.strip().startswith(key.split("\\")[0]) is False and l.strip()]
                for line in entries:
                    lower = line.lower()
                    if any(frag in lower for frag in ["\\temp\\", "\\appdata\\local\\temp", "powershell -enc", "-windowstyle hidden"]):
                        findings.append(Finding(
                            category="forensics",
                            title=f"Suspicious autorun entry in {key}",
                            severity=Severity.HIGH,
                            description="A startup (Run key) entry references a temp path or hidden/encoded PowerShell execution.",
                            evidence=line.strip()[:250],
                            recommendation="Investigate this autorun entry; remove if not a known legitimate application.",
                            mitre_technique="T1547.001",
                            platform="windows",
                            source_plugin=self.name,
                        ))

        tasks = run(["powershell", "-NoProfile", "-Command",
                      "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | "
                      "Select-Object TaskName,TaskPath | ConvertTo-Json"], timeout=25)
        data["scheduled_tasks"] = tasks.stdout if tasks.ok else None

        services = run(["powershell", "-NoProfile", "-Command",
                         "Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq 'Auto'} | "
                         "Select-Object Name,PathName,StartName | ConvertTo-Json"], timeout=25)
        data["services"] = services.stdout if services.ok else None
        if services.ok and services.stdout:
            low = services.stdout.lower()
            if "\\temp\\" in low or "\\users\\public\\" in low:
                findings.append(Finding(
                    category="forensics",
                    title="Auto-start service binary path in a user-writable location",
                    severity=Severity.HIGH,
                    description="One or more auto-start services point to an executable under Temp or Public, "
                                 "a common technique for persistence and privilege escalation.",
                    evidence=services.stdout[:300],
                    recommendation="Identify and validate the responsible service; unsigned binaries in writable paths warrant removal.",
                    mitre_technique="T1543.003",
                    platform="windows",
                    source_plugin=self.name,
                ))

        return ScanResult(
            plugin_name=self.name,
            category=self.category,
            platform=self.platform_supported,
            started_at=started,
            finished_at=now(),
            data=data,
            findings=findings,
        )
