"""
Network Scanner (Priority 1)
Interfaces, IPs, MACs, listening ports, established connections, gateway/DNS.
Read-only - never binds, never scans other hosts.
"""
from __future__ import annotations

import platform
import socket

import psutil

from bsen.core.models import Finding, ScanResult, Severity, now
from bsen.core.plugin import ScannerPlugin
from bsen.utils.shell import run

RISKY_PORTS = {
    21: ("FTP", Severity.MEDIUM),
    23: ("Telnet", Severity.HIGH),
    135: ("MS-RPC", Severity.MEDIUM),
    139: ("NetBIOS", Severity.MEDIUM),
    445: ("SMB", Severity.MEDIUM),
    3389: ("RDP", Severity.HIGH),
    5900: ("VNC", Severity.HIGH),
}


class NetworkScanner(ScannerPlugin):
    name = "network_scanner"
    category = "network"
    platform_supported = "any"
    priority = 1

    def _gateway_dns(self) -> dict:
        gw, dns = None, []
        try:
            if platform.system() == "Linux":
                res = run(["ip", "route", "show", "default"])
                if res.ok and res.stdout:
                    parts = res.stdout.split()
                    if "via" in parts:
                        gw = parts[parts.index("via") + 1]
                try:
                    with open("/etc/resolv.conf") as fh:
                        for line in fh:
                            if line.strip().startswith("nameserver"):
                                dns.append(line.split()[1])
                except FileNotFoundError:
                    pass
            elif platform.system() == "Windows":
                res = run(["ipconfig"])
                for line in res.stdout.splitlines():
                    low = line.lower()
                    if "default gateway" in low and ":" in line:
                        val = line.split(":", 1)[1].strip()
                        if val:
                            gw = val
                    if "dns servers" in low and ":" in line:
                        val = line.split(":", 1)[1].strip()
                        if val:
                            dns.append(val)
        except Exception:
            pass
        return {"gateway": gw, "dns": dns}

    def scan(self) -> ScanResult:
        started = now()
        findings: list[Finding] = []

        interfaces = {}
        for name, addrs in psutil.net_if_addrs().items():
            entry = {"addresses": []}
            for a in addrs:
                fam = str(a.family)
                entry["addresses"].append({
                    "family": fam,
                    "address": a.address,
                    "netmask": a.netmask,
                })
            interfaces[name] = entry

        stats = {n: s._asdict() for n, s in psutil.net_if_stats().items()}

        listening = []
        established = []
        try:
            for c in psutil.net_connections(kind="inet"):
                entry = {
                    "fd": c.fd,
                    "family": str(c.family),
                    "type": str(c.type),
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                    "status": c.status,
                    "pid": c.pid,
                }
                if c.status == "LISTEN":
                    listening.append(entry)
                    port = c.laddr.port if c.laddr else None
                    if port in RISKY_PORTS:
                        svc, sev = RISKY_PORTS[port]
                        findings.append(Finding(
                            category="network",
                            title=f"Sensitive service listening: {svc} (port {port})",
                            severity=sev,
                            description=f"A {svc} service is listening on port {port}.",
                            evidence=str(entry),
                            recommendation=f"Confirm {svc} exposure is required and restricted to trusted networks/firewall rules.",
                            mitre_technique="T1021" if svc in ("RDP", "VNC", "SMB") else None,
                            platform="any",
                            source_plugin=self.name,
                        ))
                elif c.status == "ESTABLISHED":
                    established.append(entry)
        except (psutil.AccessDenied, PermissionError):
            findings.append(Finding(
                category="network",
                title="Insufficient privileges for full connection enumeration",
                severity=Severity.INFO,
                description="Some socket details require elevated/administrator privileges.",
                recommendation="Re-run BSEN with elevated privileges for complete network visibility.",
                platform="any",
                source_plugin=self.name,
            ))

        gw_dns = self._gateway_dns()

        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            local_ip = None

        data = {
            "hostname": socket.gethostname(),
            "local_ip": local_ip,
            "interfaces": interfaces,
            "interface_stats": stats,
            "gateway": gw_dns["gateway"],
            "dns_servers": gw_dns["dns"],
            "listening_ports": listening,
            "established_connections": established[:200],  # cap for report size
            "listening_count": len(listening),
            "established_count": len(established),
        }

        if len(listening) > 25:
            findings.append(Finding(
                category="network",
                title="Large number of listening ports",
                severity=Severity.LOW,
                description=f"{len(listening)} listening sockets found - larger attack surface than typical for an endpoint.",
                recommendation="Review each listening service and disable anything unnecessary.",
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
