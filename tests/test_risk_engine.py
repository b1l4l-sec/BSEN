from bsen.core.models import Finding, ScanResult, Severity
from bsen.risk_engine.engine import compute_risk
from bsen.risk_engine.analyst import generate_analyst_report


def _result_with(findings):
    return ScanResult(
        plugin_name="p", category="c", platform="any",
        started_at=0, finished_at=1, findings=findings,
    )


def test_compute_risk_no_findings_is_perfect_score():
    risk = compute_risk([_result_with([])])
    assert risk.security_score == 100
    assert risk.grade == "A+"
    assert risk.total_findings == 0


def test_compute_risk_penalizes_critical_findings():
    f = Finding(category="c", title="t", severity=Severity.CRITICAL, description="d")
    risk = compute_risk([_result_with([f])])
    assert risk.total_findings == 1
    assert risk.security_score < 100
    assert risk.findings_by_severity["CRITICAL"] == 1


def test_analyst_verdict_flags_critical():
    f = Finding(category="c", title="t", severity=Severity.CRITICAL, description="d",
                recommendation="fix it now")
    results = [_result_with([f])]
    risk = compute_risk(results)
    analyst = generate_analyst_report(results, risk)
    assert "CRITICAL" in analyst.verdict.upper() or "AT RISK" in analyst.verdict.upper()
    assert "fix it now" in analyst.recommended_actions


def test_analyst_healthy_verdict_when_clean():
    results = [_result_with([])]
    risk = compute_risk(results)
    analyst = generate_analyst_report(results, risk)
    assert "HEALTHY" in analyst.verdict.upper()
