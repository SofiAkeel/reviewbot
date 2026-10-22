"""
Command-Line Interface (CLI) for AI Security Review Bot.
Dispatches scans across secrets, dependencies, and static analysis,
runs AI false-positive triage, formats reports, and returns appropriate exit codes for CI/CD.
"""
from __future__ import annotations
import argparse
import logging
import os
import sys
import time
from typing import List, Literal, Tuple

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from models import Finding
from scanner.secrets_scan import scan_secrets
from scanner.dependencies import scan_dependencies
from scanner.static_analysis import scan_static
from ai import GeminiClient, MockLLM, triage
from report import build_markdown, write_json

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("reviewbot")

EXCLUDE_DIRS = {".git", "venv", ".venv", "__pycache__", "node_modules", ".pytest_cache"}


def collect_files(folder: str) -> List[str]:
    collected = []
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for file in files:
            collected.append(os.path.join(root, file))
    return collected


def scan_folder(
    folder: str,
    ai_mode: Literal["none", "mock", "gemini"] = "none",
    min_confidence: float = 0.6,
) -> Tuple[List[Finding], float, bool]:
    if not os.path.isdir(folder):
        raise ValueError(f"Scan target is not a directory: {folder}")

    start_time = time.time()
    target_files = collect_files(folder)
    findings: List[Finding] = []
    findings.extend(scan_secrets(target_files))
    findings.extend(scan_dependencies(target_files))
    findings.extend(scan_static(target_files))

    ai_used = ai_mode != "none" and bool(findings)
    if ai_used:
        llm = MockLLM() if ai_mode == "mock" else GeminiClient()
        findings = triage(findings, llm, min_confidence=min_confidence)

    return findings, time.time() - start_time, ai_used


def main():
    parser = argparse.ArgumentParser(description="AI Security Review Bot")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("folder")
    scan_parser.add_argument("--no-ai", action="store_true")
    scan_parser.add_argument("--mock", action="store_true")
    scan_parser.add_argument("--changed-files", nargs="*", default=None)
    scan_parser.add_argument("--json", default="results.json")
    scan_parser.add_argument("--report", default="report.md")
    scan_parser.add_argument("--min-confidence", type=float, default=0.6)

    args = parser.parse_args()
    if args.changed_files:
        start_time = time.time()
        target_files = args.changed_files
        findings: List[Finding] = []
        findings.extend(scan_secrets(target_files))
        findings.extend(scan_dependencies(target_files))
        findings.extend(scan_static(target_files))
        ai_used = not args.no_ai and bool(findings)
        if ai_used:
            llm = MockLLM() if args.mock else GeminiClient()
            findings = triage(findings, llm, min_confidence=args.min_confidence)
        duration = time.time() - start_time
    else:
        ai_mode = "none" if args.no_ai else "mock" if args.mock else "gemini"
        findings, duration, ai_used = scan_folder(
            args.folder, ai_mode=ai_mode, min_confidence=args.min_confidence
        )
    report_md = build_markdown(findings, duration, ai_used)
    with open(args.report, "w", encoding="utf-8") as f:
        f.write(report_md)
    write_json(findings, args.json)

    active_critical_or_high = any(
        not f.suppressed and f.severity.upper() in {"CRITICAL", "HIGH"}
        for f in findings
    )
    sys.exit(1 if active_critical_or_high else 0)


if __name__ == "__main__":
    main()