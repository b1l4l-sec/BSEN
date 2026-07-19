"""
System Scanner (Priority 1)
Hostname, OS, kernel, CPU, RAM, disk, uptime, users, VM/container detection.
Cross-platform via psutil + platform (read-only).
"""
from __future__ import annotations

import os
import platform
import socket
import getpass
from datetime import datetime

import psutil

from bsen.core.models import Finding, ScanResult, Severity, now
from bsen.core.plugin import ScannerPlugin


class SystemScanner(ScannerPlugin):
    name = "system_scanner"
    category = "system"
    platform_supported = "any"
    priority = 1

    def _detect_virtualization(self) -> str:
        indicators = {
            "VirtualBox": ["virtualbox", "vbox"],
            "VMware": ["vmware"],
            "Hyper-V": ["hyper-v", "microsoft corporation"],
            "WSL": ["microsoft"] if "microsoft" in platform.release().lower() else [],
            "KVM/QEMU": ["qemu", "kvm"],
        }
        try:
            manufacturer = ""
            if platform.system() == "Linux":
                for p in ("/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/product_name"):
                    if os.path.exists(p):
                        with open(p) as fh:
                            manufacturer += fh.read().lower() + " "
            elif platform.system() == "Windows":
                from bsen.utils.shell import run
                res = run(["wmic", "computersystem", "get", "model,manufacturer"])
                manufacturer = res.stdout.lower()
        except Exception:
            manufacturer = ""

        if "microsoft" in platform.release().lower() and platform.system() == "Linux":
            return "WSL"
        for vm_name, keywords in indicators.items():
            for kw in keywords:
                if kw and kw in manufacturer:
                    return vm_name
        return "Physical / Unknown"

    def scan(self) -> ScanResult:
        started = now()
        findings: list[Finding] = []

        uname = platform.uname()
        boot_ts = psutil.boot_time()
        uptime_s = now() - boot_ts

        vm = self._detect_virtualization()
        if vm != "Physical / Unknown":
            findings.append(Finding(
                category="system",
                title="Virtualized environment detected",
                severity=Severity.INFO,
                description=f"Host appears to be running under: {vm}",
                evidence=vm,
                recommendation="Informational - confirm this matches the expected deployment context.",
                platform="any",
                source_plugin=self.name,
            ))

        try:
            users = [u._asdict() for u in psutil.users()]
        except Exception:
            users = []

        cpu_count = psutil.cpu_count(logical=True)
        vm_mem = psutil.virtual_memory()
        disks = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total_gb": round(usage.total / (1024**3), 2),
                    "used_percent": usage.percent,
                })
            except (PermissionError, OSError):
                continue

        data = {
            "hostname": socket.gethostname(),
            "current_user": getpass.getuser(),
            "os_system": uname.system,
            "os_release": uname.release,
            "os_version": uname.version,
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "boot_time": datetime.fromtimestamp(boot_ts).isoformat(),
            "uptime_hours": round(uptime_s / 3600, 2),
            "cpu_logical_cores": cpu_count,
            "cpu_physical_cores": psutil.cpu_count(logical=False),
            "cpu_percent": psutil.cpu_percent(interval=0.3),
            "ram_total_gb": round(vm_mem.total / (1024**3), 2),
            "ram_used_percent": vm_mem.percent,
            "disks": disks,
            "logged_in_users": users,
            "virtualization": vm,
            "timezone": datetime.now().astimezone().tzname(),
        }

        if vm_mem.percent > 90:
            findings.append(Finding(
                category="system",
                title="High memory pressure",
                severity=Severity.LOW,
                description=f"System memory usage is at {vm_mem.percent}%.",
                evidence=f"ram_used_percent={vm_mem.percent}",
                recommendation="Investigate memory-heavy processes if this is unexpected.",
                platform="any",
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
