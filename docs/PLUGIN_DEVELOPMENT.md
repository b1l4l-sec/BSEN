# Writing a BSEN Plugin

Every scanner is a plugin. No core file needs to change to add one —
just drop a new `.py` file in the right folder:

- `bsen/scanners/common/` — runs on both Windows and Linux
- `bsen/scanners/windows/` — Windows only
- `bsen/scanners/linux/` — Linux only

## Minimal example

```python
# bsen/scanners/common/my_check.py
from bsen.core.models import Finding, ScanResult, Severity, now
from bsen.core.plugin import ScannerPlugin


class MyCheckScanner(ScannerPlugin):
    name = "my_check_scanner"          # unique, snake_case
    category = "hardening"             # system | network | security | forensics
                                        # | threat_hunting | hardening
    platform_supported = "any"         # "any" | "windows" | "linux"
    priority = 2                       # 1 = MVP core, 2 = extended, 3 = advanced

    def scan(self) -> ScanResult:
        started = now()
        findings = []

        # ... do your READ-ONLY inspection here ...
        suspicious = False

        if suspicious:
            findings.append(Finding(
                category=self.category,
                title="Short human-readable title",
                severity=Severity.MEDIUM,
                description="What you found, in plain language.",
                evidence="the exact data point(s) that triggered this",
                recommendation="What the operator should do about it.",
                mitre_technique="T1059",   # optional
                platform=self.platform_supported,
                source_plugin=self.name,
            ))

        return ScanResult(
            plugin_name=self.name,
            category=self.category,
            platform=self.platform_supported,
            started_at=started,
            finished_at=now(),
            data={"whatever_raw_data": "you want in the JSON report"},
            findings=findings,
        )
```

That's it — run `bsen list-plugins` and it will appear automatically.

## Rules every plugin must follow

1. **Read-only.** Never write to the registry, filesystem, services, or
   any system configuration. Never disable/enable/kill/modify anything.
2. **Never crash the run.** `ScannerPlugin.safe_scan()` already wraps your
   `scan()` in a try/except, but prefer to handle expected failures
   (missing tool, permission denied) gracefully and report them as an
   `INFO` finding rather than raising.
3. **Use `bsen.utils.shell.run()`** for any subprocess call — it's the
   single audited chokepoint for shelling out, has a timeout, and never
   raises.
4. **Populate `evidence`** with the actual data that justifies the
   finding — reports should be defensible without re-running the scan.
5. **Map to MITRE ATT&CK** where a clear technique exists; leave `None`
   otherwise rather than guessing.
6. **Keep `data` bounded.** Cap large lists (processes, connections,
   files) so JSON reports stay a reasonable size — see `process_scanner.py`
   and `network_scanner.py` for the pattern (`[:500]`, `[:200]`, etc).

## Testing your plugin

```bash
python -m bsen.cli list-plugins        # confirm it's discovered
python -m bsen.cli scan --quick        # or a full `scan` if it's not system/network
```

Add a unit test under `tests/` that instantiates your plugin and calls
`.safe_scan()`, asserting it returns a `ScanResult` with no unexpected
`error` on a clean environment.
