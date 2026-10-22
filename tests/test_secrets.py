"""
Unit tests for secrets detection, masking, and entropy calculations.
"""
import os
import tempfile
import pytest
from scanner.secrets_scan import (
    scan_secrets,
    mask_secret,
    calculate_shannon_entropy,
    is_placeholder
)


def test_mask_secret():
    raw = "AKIAIOSFODNN7EXAMPLE"
    masked = mask_secret(raw)
    assert masked.startswith("AKIA")
    assert masked.endswith("MPLE")
    assert "OSFODNN7EXA" not in masked
    assert "*" in masked
    assert mask_secret("short") == "****"


def test_entropy_calculation():
    low_entropy = calculate_shannon_entropy("hello world this is a normal test string")
    assert low_entropy < 4.0

    high_entropy_str = "wK9+F4vL98aPqZ1xV7bN0mE3=="
    high_entropy = calculate_shannon_entropy(high_entropy_str)
    assert high_entropy > 4.1


def test_placeholder_filtering():
    assert is_placeholder("changeme") is True
    assert is_placeholder("your_api_key") is True
    assert is_placeholder("<INSERT_TOKEN_HERE>") is True
    assert is_placeholder("test_dummy_value") is True
    assert is_placeholder("AKIAIOSFODNN7EXAMPLE") is False


def test_scan_secrets_file_detection_and_masking():
    content = """
    # Normal comment
    AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
    GH_TOKEN = "ghp_fakeTokenForDemoAndTesting1234567890ab"
    PLACEHOLDER = "changeme"
    NORMAL_STRING = "this is a long sentence that has perfectly normal human words in it"
    RANDOM_HASH = "h7D$kP9!mZ2@vL4#qR8*yT1&"
    """
    with tempfile.NamedTemporaryFile("w+", suffix=".py", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        findings = scan_secrets([tmp_path])
        rule_ids = [f.rule_id for f in findings]

        assert "SEC001-AWS" in rule_ids
        assert "SEC002-GITHUB" in rule_ids
        assert not any("changeme" in f.snippet for f in findings)

        for f in findings:
            assert "AKIAIOSFODNN7EXAMPLE" not in f.snippet
            assert "AKIAIOSFODNN7EXAMPLE" not in f.message
            assert "ghp_fakeTokenForDemoAndTesting1234567890ab" not in f.snippet
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)