"""
Rule-based "AI Security Analyst" (Priority 3, implemented as a
deterministic rules engine rather than a live LLM call, so the tool
has zero external dependencies / API keys required to run offline).

Produces a SOC-analyst-style narrative from the aggregated findings:
verdict, executive summary, top/critical findings, recommended actions.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from bsen.core.models import ScanResult, Severity
from bsen.risk_engine.engine import RiskSummary


@dataclass
class AnalystReport:
    verdict: str
    executive_summary: str
    critical_findings: list[dict] = field(default_factory=list)
    top_findings: list[dict] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)


def _verdict_for_grade(grade: str, critical_count: int, high_count: int) -> str:
    if critical_count > 0:
        return "AT RISK - Critical issues require immediate remediation"
    if high_count > 2:
        return "ELEVATED RISK - Multiple high-severity issues detected"
    if grade in ("A+", "A"):
        return "HEALTHY - No significant security gaps identified"
    if grade in ("B", "C"):
        return "MODERATE RISK - Hardening recommended"
    return "AT RISK - Security posture needs attention"


def generate_analyst_report(results: list[ScanResult], risk: RiskSummary) -> AnalystReport:
    all_findings = [f for r in results for f in r.findings]
    critical = [f for f in all_findings if f.severity == Severity.CRITICAL]
    high = [f for f in all_findings if f.severity == Severity.HIGH]

    # Sort remaining findings by risk_score desc for a "top findings" list
    ranked = sorted(all_findings, key=lambda f: f.risk_score, reverse=True)

    verdict = _verdict_for_grade(risk.grade, len(critical), len(high))

    summary_lines = [
        f"This assessment identified {risk.total_findings} finding(s) across "
        f"{len(results)} scanner module(s), yielding a security score of "
        f"{risk.security_score}/100 (grade {risk.grade}).",
    ]
    if critical:
        summary_lines.append(
            f"{len(critical)} CRITICAL finding(s) were identified and should be treated as the top priority."
        )
    if high:
        summary_lines.append(f"{len(high)} HIGH-severity finding(s) were also identified.")
    if not all_findings:
        summary_lines.append("No security gaps were identified during this scan.")

    recommendations = []
    seen_recs = set()
    for f in ranked:
        if f.recommendation and f.recommendation not in seen_recs:
            recommendations.append(f.recommendation)
            seen_recs.add(f.recommendation)
        if len(recommendations) >= 10:
            break

    return AnalystReport(
        verdict=verdict,
        executive_summary=" ".join(summary_lines),
        critical_findings=[f.to_dict() for f in critical],
        top_findings=[f.to_dict() for f in ranked[:10]],
        recommended_actions=recommendations,
    )
