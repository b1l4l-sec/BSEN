"""
Core data models shared by every scanner plugin.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional
import time


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 5,
    Severity.HIGH: 8,
    Severity.CRITICAL: 12,
}


@dataclass
class Finding:
    """A single normalized audit finding produced by any scanner plugin."""
    category: str
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    recommendation: str = ""
    mitre_technique: Optional[str] = None
    risk_score: int = 0
    platform: str = "any"
    source_plugin: str = ""

    def __post_init__(self):
        if not self.risk_score:
            self.risk_score = SEVERITY_WEIGHT.get(Severity(self.severity), 0)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value if isinstance(self.severity, Severity) else self.severity
        return d


@dataclass
class ScanResult:
    """Result returned by a single scanner plugin."""
    plugin_name: str
    category: str
    platform: str
    started_at: float
    finished_at: float
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def duration(self) -> float:
        return round(self.finished_at - self.started_at, 3)

    def to_dict(self) -> dict:
        return {
            "plugin_name": self.plugin_name,
            "category": self.category,
            "platform": self.platform,
            "duration_sec": self.duration,
            "data": self.data,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }


def now() -> float:
    return time.time()
