"""
Risk Engine
Aggregates findings from every scan result into an overall security
score, risk score, and letter grade.
"""
from __future__ import annotations

from dataclasses import dataclass

from bsen.core.models import ScanResult, Severity, SEVERITY_WEIGHT


@dataclass
class RiskSummary:
    total_findings: int
    findings_by_severity: dict[str, int]
    total_risk_score: int
    security_score: int  # 0-100, higher is better
    grade: str


def _grade_for_score(score: int) -> str:
    if score >= 97:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def compute_risk(results: list[ScanResult]) -> RiskSummary:
    by_sev = {s.value: 0 for s in Severity}
    total_risk = 0
    total_findings = 0

    for r in results:
        for f in r.findings:
            sev = f.severity.value if isinstance(f.severity, Severity) else f.severity
            by_sev[sev] = by_sev.get(sev, 0) + 1
            total_risk += f.risk_score
            total_findings += 1

    # Security score starts at 100 and is reduced by weighted findings,
    # with diminishing marginal penalty so a single finding doesn't
    # look identical to a system riddled with them but also doesn't
    # collapse the score to 0 immediately.
    penalty = min(100, total_risk)
    security_score = max(0, 100 - penalty)

    return RiskSummary(
        total_findings=total_findings,
        findings_by_severity=by_sev,
        total_risk_score=total_risk,
        security_score=security_score,
        grade=_grade_for_score(security_score),
    )
