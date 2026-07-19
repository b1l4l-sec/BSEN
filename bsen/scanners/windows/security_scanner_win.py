"""
Windows Security Scanner (Priority 1)
Defender status, Firewall profiles, BitLocker, Secure Boot, UAC.
All checks are read-only WMI/PowerShell/reg *queries* - nothing is changed.
"""
from __future__ import annotations

from bsen.core.models import Finding, ScanResult, Severity, now
from bsen.core.plugin import ScannerPlugin
from bsen.utils.shell import run


class WindowsSecurityScanner(ScannerPlugin):
    name = "windows_security_scanner"
    category = "security"
    platform_supported = "windows"
    priority = 1

    def _ps(self, cmd: str):
        return run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd], timeout=25)

    def scan(self) -> ScanResult:
        started = now()
        findings: list[Finding] = []
        data = {}

        # Windows Defender status (read-only query)
        defender = self._ps(
            "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
            "AntivirusSignatureLastUpdated,BehaviorMonitorEnabled | ConvertTo-Json"
        )
        data["windows_defender_raw"] = defender.stdout
        if defender.ok and "false" in defender.stdout.lower() and "antivirusenabled" in defender.stdout.lower():
            findings.append(Finding(
                category="security",
                title="Windows Defender real-time protection disabled",
                severity=Severity.CRITICAL,
                description="Windows Defender antivirus or real-time protection appears to be disabled.",
                evidence=defender.stdout[:300],
                recommendation="Re-enable Windows Defender real-time protection immediately.",
                mitre_technique="T1562.001",
                platform="windows",
                source_plugin=self.name,
            ))

        # Firewall profile status
        firewall = self._ps("Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json")
        data["firewall_raw"] = firewall.stdout
        if firewall.ok and '"Enabled": false' in firewall.stdout.replace(" ", ""):
            pass  # handled generically below
        if firewall.ok and "false" in firewall.stdout.lower():
            findings.append(Finding(
                category="security",
                title="A Windows Firewall profile is disabled",
                severity=Severity.HIGH,
                description="One or more Windows Firewall profiles (Domain/Private/Public) is disabled.",
                evidence=firewall.stdout[:300],
                recommendation="Enable the Windows Firewall on all network profiles.",
                mitre_technique="T1562.004",
                platform="windows",
                source_plugin=self.name,
            ))

        # BitLocker
        bitlocker = self._ps(
            "Get-BitLockerVolume -MountPoint C: | Select-Object MountPoint,ProtectionStatus | ConvertTo-Json"
        )
        data["bitlocker_raw"] = bitlocker.stdout
        if bitlocker.ok and "0" in bitlocker.stdout and "protectionstatus" in bitlocker.stdout.lower():
            findings.append(Finding(
                category="security",
                title="BitLocker not protecting system drive",
                severity=Severity.MEDIUM,
                description="BitLocker disk encryption does not appear to be enabled on C:.",
                evidence=bitlocker.stdout[:300],
                recommendation="Enable BitLocker for the system volume, especially on portable devices.",
                platform="windows",
                source_plugin=self.name,
            ))

        # Secure Boot
        secure_boot = self._ps("Confirm-SecureBootUEFI")
        data["secure_boot_enabled"] = secure_boot.stdout
        if secure_boot.ok and "false" in secure_boot.stdout.lower():
            findings.append(Finding(
                category="security",
                title="Secure Boot disabled",
                severity=Severity.MEDIUM,
                description="UEFI Secure Boot is disabled on this system.",
                recommendation="Enable Secure Boot in UEFI/BIOS settings if hardware supports it.",
                platform="windows",
                source_plugin=self.name,
            ))

        # UAC
        uac = run(["reg", "query",
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                    "/v", "EnableLUA"])
        data["uac_raw"] = uac.stdout
        if uac.ok and "0x0" in uac.stdout:
            findings.append(Finding(
                category="security",
                title="User Account Control (UAC) disabled",
                severity=Severity.HIGH,
                description="UAC is disabled, removing a key privilege-escalation barrier.",
                evidence=uac.stdout,
                recommendation="Re-enable UAC (EnableLUA=1).",
                mitre_technique="T1548.002",
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
