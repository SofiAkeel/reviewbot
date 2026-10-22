"""
Static code analysis scanner using Bandit.
Executes Bandit on Python source files, captures AST security flaws, and normalizes findings.
"""
from __future__ import annotations
import json
import logging
import os
import shutil
import subprocess
import sys
from typing import List
from models import Finding

logger = logging.getLogger(__name__)


def scan_static(files: List[str]) -> List[Finding]:
    py_files = [f for f in files if f.endswith(".py") and os.path.isfile(f)]
    if not py_files:
        return []

    cmd = ["bandit", "-f", "json", "-q"] + py_files
    if not shutil.which("bandit"):
        cmd = [sys.executable, "-m", "bandit", "-f", "json", "-q"] + py_files

    findings: List[Finding] = []
    try:
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120
        )
        output = process.stdout.strip()
        if not output:
            return []

        data = json.loads(output)
        for item in data.get("results", []):
            raw_sev = str(item.get("issue_severity", "MEDIUM")).upper()
            findings.append(Finding(
                scanner="static",
                rule_id=str(item.get("test_id", "B000")),
                severity=raw_sev,
                file=str(item.get("filename", "")),
                line=int(item.get("line_number", 1)),
                snippet=str(item.get("code", "")).strip(),
                message=str(item.get("issue_text", "Static analysis security issue detected"))
            ))
    except Exception as err:
        logger.warning("Bandit scan encountered error: %s", err)
        return []

    return findings