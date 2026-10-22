"""
Unit tests for markdown report generation, marker preservation, and CI/CD exit code logic.
"""
from models import Finding
from report import build_markdown, MARKER


def test_markdown_report_structure_and_marker():
    findings = [
        Finding(
            scanner="static",
            rule_id="B608",
            severity="HIGH",
            file="app.py",
            line=12,
            snippet="query = f'SELECT * FROM users WHERE name={name}'",
            message="Possible SQL injection",
            ai={
                "explanation": "Formatted SQL queries allow attackers to manipulate DB queries.",
                "risk": "Data exfiltration or database corruption.",
                "suggested_fix": "cursor.execute('SELECT * FROM users WHERE name=?', (name,))",
                "confidence": 0.95,
                "false_positive": False,
            }
        ),
        Finding(
            scanner="static",
            rule_id="B101",
            severity="LOW",
            file="safe.py",
            line=4,
            snippet="assert x > 0",
            message="Use of assert",
            suppressed=True,
            suppress_reason="Classified as false alarm"
        )
    ]

    report = build_markdown(findings, scan_seconds=1.45, ai_used=True)
    assert MARKER in report
    assert "1 active issue(s) found" in report
    assert "1 suppressed as false alarms" in report
    assert "app.py" in report
    assert "B608" in report


def test_exit_code_decision_logic():
    def should_fail_ci(findings_list):
        return any(
            not f.suppressed and f.severity.upper() in {"CRITICAL", "HIGH"}
            for f in findings_list
        )

    f_high = Finding(scanner="static", rule_id="B608", severity="HIGH", file="a.py", line=1, message="SQLi")
    assert should_fail_ci([f_high]) is True

    f_high_suppressed = Finding(scanner="static", rule_id="B608", severity="HIGH", file="a.py", line=1, message="SQLi", suppressed=True)
    assert should_fail_ci([f_high_suppressed]) is False