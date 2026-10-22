"""
Data models and shared representations for AI Security Review Bot.
"""
from __future__ import annotations
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class Finding(BaseModel):
    """
    Standard security finding produced by any scanner (secrets, dependency, static).
    Shared across the entire reviewbot pipeline: scanners, AI triage, report, CLI, and dashboard.
    """
    scanner: str = Field(description="Origin scanner: 'secrets' | 'dependency' | 'static'")
    rule_id: str = Field(description="Unique rule ID or vulnerability identifier")
    severity: str = Field(description="Severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'")
    file: str = Field(description="File path relative to repository root")
    line: int = Field(default=1, description="Line number of the issue")
    snippet: str = Field(default="", description="Code snippet where issue occurs (MUST be masked for secrets)")
    message: str = Field(description="Short human-readable summary of the detected problem")
    ai: Optional[Dict[str, Any]] = Field(
        default=None,
        description="AI triage result dict with keys: explanation, risk, suggested_fix, confidence, false_positive"
    )
    suppressed: bool = Field(
        default=False,
        description="Whether this finding was suppressed (e.g. determined as false alarm by AI)"
    )
    suppress_reason: Optional[str] = Field(
        default=None,
        description="Explanation of why the finding was suppressed or if AI was unavailable"
    )


def severity_rank(sev: str) -> int:
    """
    Returns an integer rank for ordering findings by importance.
    CRITICAL (4) > HIGH (3) > MEDIUM (2) > LOW (1).
    """
    mapping = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }
    return mapping.get(str(sev).strip().upper(), 0)