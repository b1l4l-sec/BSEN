"""
Linux Security Scanner (Priority 1)
UFW/firewalld, SELinux/AppArmor, auditd, fail2ban, SSH config hardening.
Read-only status queries only.
"""
from __future__ import annotations

import os

from bsen.core.models import Finding, ScanResult, Severity, now
from bsen.core.plugin import ScannerPlugin
from bsen.utils.shell import run


class LinuxSecurityScanner(ScannerPlugin):
    name = "linux_security_scanner"
    category = "security"
    platform_supported = "linux"
    priority = 1

    def scan(self) -> ScanResult:
        started = now()
        findings: list[Finding] = []
        data = {}

        ufw = run(["ufw", "status"])
        firewalld = run(["firewall-cmd", "--state"])
        data["ufw_status"] = ufw.stdout if ufw.returncode is not None else "not installed"
        data["firewalld_status"] = firewalld.stdout if firewalld.returncode is not None else "not installed"

        fw_active = ("active" in ufw.stdout.lower()) or ("running" in firewalld.stdout.lower())
        fw_checked = ufw.returncode is not None or firewalld.returncode is not None
        if fw_checked and not fw_active:
            findings.append(Finding(
                category="security",
                title="No active host firewall detected",
                severity=Severity.HIGH,
                description="Neither ufw nor firewalld reports an active/running state.",
                evidence=f"ufw={ufw.stdout[:100]} firewalld={firewalld.stdout[:100]}",
                recommendation="Enable ufw or firewalld and configure a default-deny inbound policy.",
                mitre_technique="T1562.004",
                platform="linux",
                source_plugin=self.name,
            ))

        selinux = run(["getenforce"])
        apparmor = run(["aa-status", "--enabled"])
        data["selinux_mode"] = selinux.stdout if selinux.returncode is not None else "not installed"
        data["apparmor_enabled"] = apparmor.ok if apparmor.returncode is not None else "not installed"

        if selinux.returncode is not None and selinux.stdout.strip().lower() == "disabled":
            findings.append(Finding(
                category="security",
                title="SELinux disabled",
                severity=Severity.MEDIUM,
                description="SELinux is installed but set to Disabled.",
                recommendation="Set SELinux to Enforcing (or Permissive during tuning) where policy allows.",
                platform="linux",
                source_plugin=self.name,
            ))

        auditd = run(["systemctl", "is-active", "auditd"])
        data["auditd_active"] = auditd.stdout
        if auditd.returncode is not None and auditd.stdout.strip() != "active":
            findings.append(Finding(
                category="security",
                title="auditd not active",
                severity=Severity.LOW,
                description="The Linux Audit daemon (auditd) is not currently active, reducing forensic visibility.",
                recommendation="Enable auditd for system call and file-integrity auditing.",
                platform="linux",
                source_plugin=self.name,
            ))

        fail2ban = run(["systemctl", "is-active", "fail2ban"])
        data["fail2ban_active"] = fail2ban.stdout

        # SSH hardening checks
        sshd_config = "/etc/ssh/sshd_config"
        ssh_findings = {}
        if os.path.exists(sshd_config):
            try:
                with open(sshd_config) as fh:
                    content = fh.read()
                ssh_findings["permit_root_login"] = "PermitRootLogin" in content
                if "PermitRootLogin yes" in content.replace("  ", " "):
                    findings.append(Finding(
                        category="security",
                        title="SSH PermitRootLogin enabled",
                        severity=Severity.HIGH,
                        description="sshd_config allows direct root login over SSH.",
                        evidence="PermitRootLogin yes",
                        recommendation="Set 'PermitRootLogin no' and use sudo with a non-root account instead.",
                        mitre_technique="T1078",
                        platform="linux",
                        source_plugin=self.name,
                    ))
                if "PasswordAuthentication yes" in content.replace("  ", " "):
                    findings.append(Finding(
                        category="security",
                        title="SSH password authentication enabled",
                        severity=Severity.MEDIUM,
                        description="sshd_config allows password-based authentication instead of key-only.",
                        recommendation="Disable password authentication and enforce SSH key-based login.",
                        platform="linux",
                        source_plugin=self.name,
                    ))
            except PermissionError:
                ssh_findings["error"] = "permission denied reading sshd_config"
        data["ssh_config_flags"] = ssh_findings

        return ScanResult(
            plugin_name=self.name,
            category=self.category,
            platform=self.platform_supported,
            started_at=started,
            finished_at=now(),
            data=data,
            findings=findings,
        )
