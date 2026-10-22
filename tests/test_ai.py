"""
Unit tests for AI triage, prompt secret redaction, and fallback handling.
"""
import json
import os
import pytest
from models import Finding
import ai
from ai import triage, MockLLM, redact_secrets


@pytest.fixture(autouse=True)
def isolate_ai_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(ai, "AI_CACHE_FILE", str(tmp_path / "ai_cache.json"))


class RecordingClient:
    def __init__(self, response_text: str):
        self.recorded_prompt = ""
        self.call_count = 0
        self.response_text = response_text

    def generate_json(self, prompt: str) -> str:
        self.call_count += 1
        self.recorded_prompt = prompt
        return self.response_text


def test_mock_llm_triage():
    finding_real = Finding(
        scanner="static",
        rule_id="B608",
        severity="HIGH",
        file="app.py",
        line=10,
        snippet="query = f'SELECT * FROM users WHERE id = {user_id}'",
        message="Possible SQL injection"
    )
    finding_safe = Finding(
        scanner="static",
        rule_id="B303",
        severity="MEDIUM",
        file="safe_examples.py",
        line=5,
        snippet="hashlib.md5(data).hexdigest()",
        message="Use of insecure MD5 hash"
    )

    llm = MockLLM()
    results = triage([finding_real, finding_safe], llm)

    assert len(results) == 2
    assert results[0].suppressed is False
    assert results[0].ai["false_positive"] is False
    assert results[0].ai["confidence"] >= 0.8

    assert results[1].suppressed is True
    assert results[1].ai["false_positive"] is True
    assert "false alarm" in results[1].suppress_reason.lower()


def test_secrets_are_redacted_from_prompt():
    fake_client = RecordingClient("[]")
    secret_key = "AKIAIOSFODNN7EXAMPLE"
    secret_token = "ghp_fakeTokenForDemoAndTesting1234567890ab"

    finding = Finding(
        scanner="secrets",
        rule_id="SEC001-AWS",
        severity="CRITICAL",
        file="config.py",
        line=1,
        snippet=f"AWS_KEY = '{secret_key}' and token '{secret_token}'",
        message="Hardcoded credentials"
    )

    triage([finding], fake_client)
    assert secret_key not in fake_client.recorded_prompt
    assert secret_token not in fake_client.recorded_prompt
    assert "[HIDDEN_SECRET]" in fake_client.recorded_prompt


def make_finding(severity="MEDIUM", scanner="static", rule_id="TEST", snippet="code"):
    return Finding(
        scanner=scanner,
        rule_id=rule_id,
        severity=severity,
        file="app.py",
        line=1,
        snippet=snippet,
        message=f"Finding for {rule_id}",
    )


def successful_response(prompt):
    import re

    indices = re.findall(r"--- FINDING (\d+) ---", prompt)
    return json.dumps([
        {
            "index": int(index),
            "explanation": "Reviewed",
            "risk": "Review",
            "suggested_fix": "Fix it",
            "confidence": 0.9,
            "false_positive": False,
        }
        for index in indices
    ])


class SuccessfulClient:
    def __init__(self):
        self.prompts = []

    def generate_json(self, prompt):
        self.prompts.append(prompt)
        return successful_response(prompt)


def test_ai_max_findings_prioritizes_severity(monkeypatch):
    monkeypatch.setenv("AI_MAX_FINDINGS", "1")
    monkeypatch.setenv("AI_DELAY_SECONDS", "0")
    client = SuccessfulClient()
    low = make_finding("LOW", rule_id="LOW")
    critical = make_finding("CRITICAL", rule_id="CRITICAL")
    medium = make_finding("MEDIUM", rule_id="MEDIUM")

    results = triage([low, critical, medium], client)

    assert len(client.prompts) == 1
    assert "Rule: CRITICAL" in client.prompts[0]
    assert "Rule: LOW" not in client.prompts[0]
    assert critical.ai["explanation"] == "Reviewed"
    assert low.ai["explanation"] == "AI explanation unavailable"
    assert medium.ai["explanation"] == "AI explanation unavailable"
    assert low.suppress_reason == "AI explanation unavailable"
    assert not low.suppressed
    assert results == [low, critical, medium]


def test_duplicate_dependency_findings_share_one_ai_item(monkeypatch):
    monkeypatch.setenv("AI_MAX_FINDINGS", "15")
    monkeypatch.setenv("AI_DELAY_SECONDS", "0")
    client = SuccessfulClient()
    first = make_finding(
        "HIGH", scanner="dependency", rule_id="GHSA-ONE",
        snippet="requests==2.0",
    )
    duplicate = make_finding(
        "MEDIUM", scanner="dependency", rule_id="GHSA-TWO",
        snippet="Requests==2.0",
    )

    results = triage([first, duplicate], client)

    assert len(client.prompts) == 1
    assert "GHSA-TWO" in client.prompts[0]
    assert first.ai == duplicate.ai
    assert all(f.ai["explanation"] == "Reviewed" for f in results)


def test_triage_prints_batch_progress_and_waits_between_batches(monkeypatch, capsys):
    monkeypatch.setenv("AI_MAX_FINDINGS", "15")
    monkeypatch.setenv("AI_DELAY_SECONDS", "12")
    sleeps = []
    monkeypatch.setattr("ai.time.sleep", sleeps.append)
    client = SuccessfulClient()
    findings = [make_finding(rule_id=f"F{i}") for i in range(6)]

    triage(findings, client)

    assert capsys.readouterr().out.splitlines() == [
        "AI batch 1/2",
        "AI batch 2/2",
        "AI triaged: 6; cached: 0; not triaged: 0",
    ]
    assert sleeps == [12.0]
    assert len(client.prompts) == 2


def test_triage_cache_skips_cached_findings(monkeypatch, capsys):
    monkeypatch.setenv("AI_MAX_FINDINGS", "15")
    monkeypatch.setenv("AI_DELAY_SECONDS", "0")
    client = SuccessfulClient()
    original = make_finding("HIGH", rule_id="CACHE-TEST", snippet="safe snippet")

    triage([original], client)
    assert len(client.prompts) == 1
    assert os.path.isfile(ai.AI_CACHE_FILE)

    cached = make_finding("HIGH", rule_id="CACHE-TEST", snippet="safe snippet")
    triage([cached], client)

    assert len(client.prompts) == 1
    assert cached.ai["explanation"] == "Reviewed"
    assert not cached.suppressed
    assert "AI triaged: 0; cached: 1; not triaged: 0" in capsys.readouterr().out


def test_triage_rate_limit_marks_batch_active_and_continues(monkeypatch, capsys):
    monkeypatch.setenv("AI_MAX_FINDINGS", "15")
    monkeypatch.setenv("AI_DELAY_SECONDS", "0")
    sleeps = []
    monkeypatch.setattr("ai.time.sleep", sleeps.append)

    class BusyThenSuccess:
        def __init__(self):
            self.calls = 0

        def generate_json(self, prompt):
            self.calls += 1
            if self.calls <= 4:
                error = RuntimeError("service unavailable")
                error.code = 503
                raise error
            return successful_response(prompt)

    client = BusyThenSuccess()
    findings = [make_finding(rule_id=f"RATE-{i}") for i in range(6)]

    triage(findings, client)

    assert client.calls == 5
    assert sleeps == [5, 10, 20]
    assert all(not finding.suppressed for finding in findings)
    assert all(
        finding.suppress_reason == "AI explanation unavailable"
        for finding in findings[:5]
    )
    assert findings[5].ai["explanation"] == "Reviewed"
    output = capsys.readouterr().out
    assert "Batch 1/2 busy, retrying in 5s" in output
    assert "AI triaged: 1; cached: 0; not triaged: 5" in output