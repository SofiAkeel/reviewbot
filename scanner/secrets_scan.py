import math
import re
from collections import Counter
from typing import List
from models import Finding

PLACEHOLDER_PATTERNS = [
    "changeme",
    "your_api_key",
    "insert_token_here",
    "test_dummy_value",
    "example_key",
    "placeholder",
    "todo",
    "fixme",
    "xxx",
    "none",
    "null",
]

REGEX_RULES = [
    (
        "SEC001-AWS",
        r"\bAKIA[0-9A-Z]{16}\b",
        "HIGH",
        "Hardcoded AWS Access Key ID detected",
    ),
    (
        "SEC002-GITHUB",
        r"\b(?:ghp|gho|github_pat)_[a-zA-Z0-9_]{20,255}\b",
        "CRITICAL",
        "Hardcoded GitHub Personal Access Token detected",
    ),
    (
        "SEC003-GOOGLE-API-KEY",
        r"\bAIza[0-9A-Za-z\-_]{35}\b",
        "HIGH",
        "Hardcoded Google API Key detected",
    ),
    (
        "SEC004-SLACK-TOKEN",
        r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b",
        "HIGH",
        "Hardcoded Slack API Token detected",
    ),
    (
        "SEC005-PRIVATE-KEY",
        r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----",
        "CRITICAL",
        "Unencrypted Private Key header detected in source code",
    ),
    (
        "SEC006-GENERIC-SECRET",
        r"(?i)\b(password|passwd|secret|token|api_key|apikey)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
        "HIGH",
        "Hardcoded credential or generic secret assignment detected",
    ),
]


def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_placeholder(value: str) -> bool:
    if not value:
        return True
    cleaned = value.strip().lower()
    if cleaned.startswith("<") and cleaned.endswith(">"):
        return True
    for pat in PLACEHOLDER_PATTERNS:
        if pat in cleaned:
            return True
    return False


def mask_secret(secret: str) -> str:
    if not secret:
        return "****"
    if len(secret) <= 8:
        return "****"
    return secret[:4] + "****" + secret[-4:]


def scan_secrets(file_paths: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    for file_path in file_paths:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            continue

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            matched_on_line = False
            for rule_id, pattern, severity, msg in REGEX_RULES:
                for match in re.finditer(pattern, line):
                    raw_val = match.group(1) if match.lastindex else match.group(0)
                    if rule_id != "SEC001-AWS" and is_placeholder(raw_val):
                        continue
                    masked_line = stripped.replace(raw_val, mask_secret(raw_val))
                    findings.append(
                        Finding(
                            scanner="secrets",
                            rule_id=rule_id,
                            severity=severity,
                            file=str(file_path),
                            line=int(line_num),
                            snippet=masked_line,
                            message=msg,
                        )
                    )
                    matched_on_line = True

            if not matched_on_line:
                for str_match in re.finditer(r"['\"]([^'\"]{16,})['\"]", line):
                    candidate = str_match.group(1)
                    if " " in candidate or is_placeholder(candidate):
                        continue
                    if calculate_shannon_entropy(candidate) > 4.1:
                        masked_line = stripped.replace(candidate, mask_secret(candidate))
                        findings.append(
                            Finding(
                                scanner="secrets",
                                rule_id="SEC007-HIGH-ENTROPY",
                                severity="MEDIUM",
                                file=str(file_path),
                                line=int(line_num),
                                snippet=masked_line,
                                message="High-entropy string (potential secret) detected",
                            )
                        )
    return findings
