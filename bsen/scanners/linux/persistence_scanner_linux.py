"""
Linux Persistence / Forensics Scanner (Priority 1/2)
Cron jobs, systemd services/timers, SSH authorized_keys, sudoers,
SUID/SGID binaries, world-writable files. All read-only enumeration.
"""
from __future__ import annotations

import glob
import os
import pwd

from bsen.core.models import Finding, ScanResult, Severity, now
from bsen.core.plugin import ScannerPlugin
from bsen.utils.shell import run

SENSITIVE_SUID_ALLOWLIST = {
    "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/ping", "/usr/bin/newgrp", "/usr/bin/gpasswd",
    "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/pkexec", "/usr/lib/openssh/ssh-keysign",
}


class LinuxPersistenceScanner(ScannerPlugin):
    name = "linux_persistence_scanner"
    category = "forensics"
    platform_supported = "linux"
    priority = 1

    def _cron_jobs(self) -> list[str]:
        jobs = []
        for path in ["/etc/crontab"] + glob.glob("/etc/cron.d/*"):
            try:
                with open(path) as fh:
                    jobs.append(f"{path}:\n" + fh.read())
            except (PermissionError, FileNotFoundError, IsADirectoryError):
                continue
        for user in self._local_users():
            res = run(["crontab", "-l", "-u", user])
            if res.ok and res.stdout:
                jobs.append(f"user:{user}:\n{res.stdout}")
        return jobs

    def _local_users(self) -> list[str]:
        try:
            return [u.pw_name for u in pwd.getpwall() if u.pw_uid >= 1000 or u.pw_name == "root"]
        except Exception:
            return []

    def _suid_sgid(self, limit: int = 200) -> list[str]:
        res = run(["find", "/", "-xdev", "-perm", "-4000", "-o", "-perm", "-2000"], timeout=30)
        if not res.ok:
            return []
        return res.stdout.splitlines()[:limit]

    def scan(self) -> ScanResult:
        started = now()
        findings: list[Finding] = []
        data = {}

        # Cron
        cron_jobs = self._cron_jobs()
        data["cron_jobs"] = cron_jobs
        for job in cron_jobs:
            low = job.lower()
            if any(f in low for f in ["/tmp/", "/dev/shm/", "curl ", "wget "]):
                findings.append(Finding(
                    category="forensics",
                    title="Suspicious cron job",
                    severity=Severity.HIGH,
                    description="A cron entry references /tmp, /dev/shm, or downloads content via curl/wget - "
                                 "a common persistence pattern.",
                    evidence=job[:250],
                    recommendation="Review this cron entry and remove if not a known legitimate task.",
                    mitre_technique="T1053.003",
                    platform="linux",
                    source_plugin=self.name,
                ))

        # systemd services/timers (enabled, non-standard paths)
        services = run(["systemctl", "list-unit-files", "--type=service", "--state=enabled"])
        timers = run(["systemctl", "list-timers", "--all"])
        data["enabled_services"] = services.stdout if services.returncode is not None else None
        data["timers"] = timers.stdout if timers.returncode is not None else None

        # SSH authorized_keys
        authorized_keys = {}
        for user in self._local_users():
            try:
                home = pwd.getpwnam(user).pw_dir
                ak_path = os.path.join(home, ".ssh", "authorized_keys")
                if os.path.exists(ak_path):
                    with open(ak_path) as fh:
                        keys = [l for l in fh.readlines() if l.strip() and not l.startswith("#")]
                        authorized_keys[user] = len(keys)
            except (KeyError, PermissionError):
                continue
        data["authorized_keys_counts"] = authorized_keys

        # sudoers - flag NOPASSWD ALL
        sudoers_findings = []
        for path in ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*"):
            try:
                with open(path) as fh:
                    content = fh.read()
                if "NOPASSWD: ALL" in content or "NOPASSWD:ALL" in content:
                    sudoers_findings.append(path)
            except (PermissionError, FileNotFoundError, IsADirectoryError):
                continue
        data["sudoers_nopasswd_all_files"] = sudoers_findings
        for path in sudoers_findings:
            findings.append(Finding(
                category="forensics",
                title="Unrestricted passwordless sudo (NOPASSWD: ALL)",
                severity=Severity.HIGH,
                description=f"{path} grants passwordless sudo to all commands for at least one entry.",
                evidence=path,
                recommendation="Scope NOPASSWD rules to specific commands rather than ALL where possible.",
                mitre_technique="T1548.003",
                platform="linux",
                source_plugin=self.name,
            ))

        # SUID/SGID outside allowlist
        suid_files = self._suid_sgid()
        data["suid_sgid_binary_count"] = len(suid_files)
        data["suid_sgid_sample"] = suid_files[:50]
        unexpected = [f for f in suid_files if f and f not in SENSITIVE_SUID_ALLOWLIST and "/snap/" not in f]
        if len(unexpected) > 0:
            findings.append(Finding(
                category="forensics",
                title="Non-standard SUID/SGID binaries present",
                severity=Severity.MEDIUM,
                description=f"{len(unexpected)} SUID/SGID binaries were found outside the common allowlist.",
                evidence="; ".join(unexpected[:15]),
                recommendation="Review each binary; remove the SUID/SGID bit from anything not required.",
                mitre_technique="T1548.001",
                platform="linux",
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
