"""
BSEN CLI - Blue Security Endpoint Navigator
Created by b1l4l-sec.
Terminal edition. Works identically on Windows Terminal / PowerShell / Linux shells.

Usage:
    python -m bsen.cli scan                       # full local audit
    python -m bsen.cli scan --quick                # system+network only
    python -m bsen.cli scan --format html,json,md  # choose report formats
    python -m bsen.cli list-plugins
    python -m bsen.cli remote --host 10.0.0.5 --user admin --os linux
"""
from __future__ import annotations

import argparse
import platform
import sys
import time
from pathlib import Path

from bsen import __version__, __author__
from bsen.core.plugin import discover_plugins
from bsen.reporting.report_generator import build_report_dict, generate_all_formats
from bsen.risk_engine.analyst import generate_analyst_report
from bsen.risk_engine.engine import compute_risk

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

PLUGIN_PACKAGES = [
    "bsen.scanners.common",
    "bsen.scanners.windows",
    "bsen.scanners.linux",
]

BANNER = r"""
██████╗ ███████╗███████╗███╗   ██╗
██╔══██╗██╔════╝██╔════╝████╗  ██║
██████╔╝███████╗█████╗  ██╔██╗ ██║
██╔══██╗╚════██║██╔══╝  ██║╚██╗██║
██████╔╝███████║███████╗██║ ╚████║
╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝
"""

EDITION = "Blue Security Endpoint Navigator"
TAGLINE = "Professional Endpoint Security Auditor & Digital Forensics Platform"

EXIT_OK = 0
EXIT_FINDINGS_ABOVE_THRESHOLD = 1
EXIT_RUNTIME_ERROR = 2

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def get_console():
    return Console() if RICH_AVAILABLE else None


def print_banner(console, quiet: bool = False) -> None:
    if quiet:
        return
    system = "Windows" if platform.system().lower().startswith("win") else "Linux"
    version = platform.release()
    arch = platform.machine()
    hostname = platform.node()

    if console:
        console.print(f"[bold cyan]{BANNER}[/bold cyan]")
        console.print(f"[bold white]{EDITION}[/bold white]  [dim]v{__version__}[/dim]")
        console.print(f"[dim]{TAGLINE}[/dim]")
        console.print(f"[dim]Created by {__author__}[/dim]\n")
        console.print(
            f"[grey62]Host[/grey62] [bold]{hostname}[/bold]   "
            f"[grey62]OS[/grey62] [bold]{system} {version}[/bold]   "
            f"[grey62]Arch[/grey62] [bold]{arch}[/bold]\n"
        )
    else:
        print(BANNER)
        print(f"{EDITION}  v{__version__}")
        print(TAGLINE)
        print(f"Created by {__author__}\n")
        print(f"Host: {hostname} | OS: {system} {version} | Arch: {arch}\n")


def run_scan(quick: bool, formats: list[str], output_dir: Path, json_only: bool = False,
             quiet: bool = False) -> tuple[Path, dict]:
    console = None if (json_only or quiet) else get_console()
    if not json_only:
        print_banner(console, quiet=quiet)

    plugins = discover_plugins(PLUGIN_PACKAGES)
    if quick:
        plugins = [p for p in plugins if p.category in ("system", "network")]

    plugins.sort(key=lambda p: p.priority)

    if not plugins:
        raise RuntimeError(
            "No scanner plugins were discovered for this platform. "
            "The installation may be corrupted - reinstall with `pip install -e .`."
        )

    results = []
    started_all = time.time()

    if console and not json_only:
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold]{task.description}"),
            BarColumn(complete_style="cyan", finished_style="green"),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            task = progress.add_task("Running scanners...", total=len(plugins))
            for plugin in plugins:
                progress.update(task, description=f"[cyan]{plugin.name}[/cyan]")
                results.append(plugin.safe_scan())
                progress.advance(task)
    else:
        for plugin in plugins:
            if not json_only and not quiet:
                print(f"[*] Running {plugin.name} ...")
            results.append(plugin.safe_scan())

    failed_plugins = [r for r in results if r.error]
    if failed_plugins and not quiet:
        warn = console.print if console else print
        for r in failed_plugins:
            msg = f"[!] Plugin '{r.plugin_name}' raised an error and was skipped (see report for details)"
            warn(f"[yellow]{msg}[/yellow]" if console else msg)

    duration = time.time() - started_all
    risk = compute_risk(results)
    analyst = generate_analyst_report(results, risk)
    report = build_report_dict(results, risk, analyst, duration)

    hostname = platform.node() or "host"
    basename = f"bsen_report_{hostname}_{int(time.time())}"

    if json_only:
        from bsen.reporting.report_generator import write_json
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir.parent / "remote_report.json" if output_dir.name == "reports" else output_dir.with_suffix(".json")
        write_json(report, json_path)
        return json_path, report

    paths = generate_all_formats(report, output_dir, basename, formats=formats)

    if not quiet:
        if console:
            _print_summary(console, report, paths)
        else:
            _print_summary_plain(report, paths)

    primary_path = paths.get("json") or next(iter(paths.values()))
    return primary_path, report


def _select_priority_findings(report: dict, limit: int = 8) -> list[dict]:
    """Critical findings first, then remaining top-ranked findings, capped at `limit`."""
    a = report["analyst"]
    critical = a["critical_findings"]
    seen_titles = {f["title"] for f in critical}
    rest = [f for f in a["top_findings"] if f["title"] not in seen_titles]
    return (critical + rest)[:limit]


def _print_summary(console, report: dict, paths: dict) -> None:
    rs = report["risk_summary"]
    a = report["analyst"]

    grade_color = {"A+": "green", "A": "green", "B": "cyan", "C": "yellow", "D": "orange3", "F": "red"}.get(rs["grade"], "white")
    sev_colors = {"CRITICAL": "bold red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "grey62"}

    console.print(Panel(
        f"[bold]{a['verdict']}[/bold]\n\n{a['executive_summary']}",
        title="[bold cyan]AI Security Analyst Verdict[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED,
    ))

    table = Table(title="Security Score", box=box.SIMPLE_HEAVY, show_header=False)
    table.add_row("Security Score", f"[bold]{rs['security_score']}/100[/bold]")
    table.add_row("Grade", f"[bold {grade_color}]{rs['grade']}[/bold {grade_color}]")
    table.add_row("Total Findings", str(rs["total_findings"]))
    console.print(table)

    sev_table = Table(title="Findings by Severity", box=box.SIMPLE)
    sev_table.add_column("Severity")
    sev_table.add_column("Count", justify="right")
    for sev, count in rs["findings_by_severity"].items():
        if count:
            sev_table.add_row(f"[{sev_colors.get(sev,'white')}]{sev}[/{sev_colors.get(sev,'white')}]", str(count))
    console.print(sev_table)

    priority = _select_priority_findings(report)
    if priority:
        findings_table = Table(title="Most Important Findings", box=box.SIMPLE_HEAVY, show_lines=True)
        findings_table.add_column("Severity", width=9)
        findings_table.add_column("Finding")
        findings_table.add_column("Recommendation")
        for f in priority:
            sev = f["severity"]
            color = sev_colors.get(sev, "white")
            findings_table.add_row(
                f"[{color}]{sev}[/{color}]",
                f"[bold]{f['title']}[/bold]\n[grey62]{f['description']}[/grey62]",
                f["recommendation"] or "-",
            )
        console.print(findings_table)

    console.print("\n[bold cyan]Reports written:[/bold cyan]")
    for fmt, p in paths.items():
        console.print(f"  [green]-[/green] {fmt.upper():<9} {p}")


def _print_summary_plain(report: dict, paths: dict) -> None:
    rs = report["risk_summary"]
    a = report["analyst"]
    print(f"\nVERDICT: {a['verdict']}")
    print(a["executive_summary"])
    print(f"\nSecurity Score: {rs['security_score']}/100 (Grade {rs['grade']})")
    print(f"Total Findings: {rs['total_findings']}")
    for sev, count in rs["findings_by_severity"].items():
        if count:
            print(f"  {sev}: {count}")

    priority = _select_priority_findings(report)
    if priority:
        print("\nMost Important Findings:")
        for f in priority:
            print(f"  [{f['severity']}] {f['title']}")
            print(f"      {f['description']}")
            if f.get("recommendation"):
                print(f"      Recommendation: {f['recommendation']}")

    print("\nReports written:")
    for fmt, p in paths.items():
        print(f"  {fmt.upper():<9} {p}")


def list_plugins() -> None:
    plugins = discover_plugins(PLUGIN_PACKAGES)
    console = get_console()
    if console:
        table = Table(title="BSEN Registered Scanner Plugins", box=box.SIMPLE_HEAVY)
        table.add_column("Plugin")
        table.add_column("Category")
        table.add_column("Platform")
        table.add_column("Priority")
        for p in sorted(plugins, key=lambda x: (x.priority, x.name)):
            table.add_row(p.name, p.category, p.platform_supported, str(p.priority))
        console.print(table)
    else:
        for p in plugins:
            print(f"{p.name:<30} {p.category:<15} {p.platform_supported:<10} priority={p.priority}")


def cmd_remote(args: argparse.Namespace) -> None:
    from bsen.remote.remote_audit import RemoteTarget, audit_target, RemoteAuditError

    target = RemoteTarget(
        host=args.host,
        username=args.user,
        password=args.password,
        ssh_key_path=args.ssh_key,
        os_hint=args.os,
        port=args.port,
    )
    print(f"[*] Auditing remote target {args.host} ({args.os}) as {args.user} ...")
    print("[*] This requires valid administrative credentials for the target you are authorized to assess.")
    try:
        report = audit_target(target)
    except RemoteAuditError as exc:
        print(f"[!] Remote audit failed: {exc}")
        sys.exit(1)

    out_dir = Path(args.output or "reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"bsen_remote_{args.host}_{int(time.time())}.json"
    import json
    out_path.write_text(json.dumps(report, indent=2, default=str))
    print(f"[+] Remote audit complete. Report saved to {out_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bsen", description=f"BSEN - {EDITION} (created by {__author__})")
    parser.add_argument("--version", action="version", version=f"BSEN {__version__} (by {__author__})")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Run a local endpoint security audit")
    scan_p.add_argument("--quick", action="store_true", help="Quick scan: system + network only")
    scan_p.add_argument("--format", default="json,md,html,csv", help="Comma separated: json,md,html,csv")
    scan_p.add_argument("--output", default="reports", help="Output directory for reports")
    scan_p.add_argument("--quiet", action="store_true", help="Suppress banner and terminal summary (still writes reports)")
    scan_p.add_argument(
        "--fail-on", choices=SEVERITY_ORDER, default=None,
        help="Exit with a non-zero status if any finding at or above this severity is present. "
             "Useful for CI/CD pipelines and scheduled compliance checks.",
    )
    scan_p.add_argument("--json-only", action="store_true", help=argparse.SUPPRESS)  # used internally by remote runs

    sub.add_parser("list-plugins", help="List all auto-discovered scanner plugins")

    remote_p = sub.add_parser("remote", help="Audit another machine on the network (requires credentials)")
    remote_p.add_argument("--host", required=True)
    remote_p.add_argument("--user", required=True)
    remote_p.add_argument("--password", default=None, help="Password (omit and use --ssh-key for Linux key auth)")
    remote_p.add_argument("--ssh-key", default=None, help="Path to SSH private key (Linux targets)")
    remote_p.add_argument("--os", choices=["linux", "windows"], default="linux")
    remote_p.add_argument("--port", type=int, default=None)
    remote_p.add_argument("--output", default="reports")

    return parser


def _exceeds_threshold(report: dict, fail_on: str) -> bool:
    threshold_idx = SEVERITY_ORDER.index(fail_on)
    by_sev = report["risk_summary"]["findings_by_severity"]
    for sev, count in by_sev.items():
        if count and SEVERITY_ORDER.index(sev) >= threshold_idx:
            return True
    return False


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            formats = [f.strip() for f in args.format.split(",")]
            _, report = run_scan(
                quick=args.quick, formats=formats, output_dir=Path(args.output),
                json_only=args.json_only, quiet=args.quiet,
            )
            if args.fail_on and _exceeds_threshold(report, args.fail_on):
                if not args.quiet:
                    print(f"\n[!] One or more findings at/above severity '{args.fail_on}' were detected.")
                return EXIT_FINDINGS_ABOVE_THRESHOLD
            return EXIT_OK

        elif args.command == "list-plugins":
            list_plugins()
            return EXIT_OK

        elif args.command == "remote":
            cmd_remote(args)
            return EXIT_OK

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        return EXIT_RUNTIME_ERROR
    except Exception as exc:  # noqa: BLE001 - top-level guard so the CLI never stack-traces at the user
        print(f"[!] BSEN encountered an unexpected error: {exc}")
        return EXIT_RUNTIME_ERROR

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
