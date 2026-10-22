"""
Evaluation script to benchmark Version A (Scanners only) vs Version B (Scanners + AI Triage).
Computes True Positives, False Alarms, Wrongly Suppressed issues, and Runtime over 3 runs.
Generates eval/results.md for project reports and viva presentations.
AI triage reuses the same project-level ai_cache.json as normal scans.
"""
from __future__ import annotations
import csv
import os
import sys
import time
from typing import List, Dict, Any, Tuple

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from models import Finding
from scanner.secrets_scan import scan_secrets
from scanner.dependencies import scan_dependencies
from scanner.static_analysis import scan_static
from ai import MockLLM, triage


def load_ground_truth(csv_path: str) -> List[Dict[str, Any]]:
    items = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            items.append({
                "file": row["file"].strip(),
                "line": int(row["line"]),
                "issue_type": row["issue_type"].strip(),
                "description": row["description"].strip(),
            })
    return items


def collect_sample_files(target_dir: str) -> List[str]:
    files = []
    for root, _, filenames in os.walk(target_dir):
        for fn in filenames:
            files.append(os.path.join(root, fn))
    return sorted(files)


def run_pipeline_once(files: List[str], use_ai: bool) -> Tuple[List[Finding], float]:
    t0 = time.time()
    findings: List[Finding] = []
    findings.extend(scan_secrets(files))
    findings.extend(scan_dependencies(files))
    findings.extend(scan_static(files))

    if use_ai:
        llm = MockLLM()
        findings = triage(findings, llm, min_confidence=0.6)

    duration = time.time() - t0
    return findings, duration


def evaluate_findings(findings: List[Finding], ground_truth: List[Dict[str, Any]]) -> Dict[str, Any]:
    posted = [f for f in findings if not f.suppressed]
    suppressed = [f for f in findings if f.suppressed]
    true_positives = 0
    false_alarms = 0
    matched_gt = set()

    for f in posted:
        f_base = os.path.basename(f.file)
        matched = False
        for i, gt in enumerate(ground_truth):
            if f_base == os.path.basename(gt["file"]) and abs(f.line - gt["line"]) <= 3:
                matched_gt.add(i)
                matched = True
                break
        if matched: true_positives += 1
        else: false_alarms += 1

    wrongly_suppressed = 0
    for s in suppressed:
        s_base = os.path.basename(s.file)
        for gt in ground_truth:
            if s_base == os.path.basename(gt["file"]) and abs(s.line - gt["line"]) <= 3:
                wrongly_suppressed += 1
                break

    return {
        "total_raw": len(findings),
        "posted": len(posted),
        "suppressed": len(suppressed),
        "true_positives": true_positives,
        "false_alarms": false_alarms,
        "wrongly_suppressed": wrongly_suppressed
    }