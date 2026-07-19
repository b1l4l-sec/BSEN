from bsen.core.models import Finding, ScanResult, Severity, now


def test_finding_autofills_risk_score():
    f = Finding(
        category="security",
        title="Test finding",
        severity=Severity.HIGH,
        description="desc",
    )
    assert f.risk_score == 8


def test_finding_respects_explicit_risk_score():
    f = Finding(
        category="security",
        title="Test finding",
        severity=Severity.LOW,
        description="desc",
        risk_score=99,
    )
    assert f.risk_score == 99


def test_scan_result_duration():
    started = now()
    result = ScanResult(
        plugin_name="p",
        category="c",
        platform="any",
        started_at=started,
        finished_at=started + 1.5,
    )
    assert result.duration == 1.5


def test_scan_result_to_dict_includes_findings():
    f = Finding(category="c", title="t", severity=Severity.INFO, description="d")
    result = ScanResult(
        plugin_name="p", category="c", platform="any",
        started_at=0, finished_at=1, findings=[f],
    )
    d = result.to_dict()
    assert d["findings"][0]["title"] == "t"
    assert d["findings"][0]["severity"] == "INFO"
