"""
Report generation module for formatting findings into GitHub PR markdown and JSON outputs.
"""
from __future__ import annotations
import json
import os
from typing import List
from models import Finding, severity_rank

MARKER = "<!-- ai-security-review-bot -->"

SEVERITY_BADGES = {
    "CRITICAL": "🔴 **CRITICAL**",
    "HIGH": "🟠 **HIGH**",
    "MEDIUM": "🟡 **MEDIUM**",
    "LOW": "🟢 **LOW**",
}


def build_markdown(findings: List[Finding], scan_seconds: float, ai_used: bool) -> str:
    posted = [f for f in findings if not f.suppressed]
    suppressed = [f for f in findings if f.suppressed]

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in posted:
        s = f.severity.upper()
        if s in counts: counts[s] += 1
        else: counts["MEDIUM"] += 1

    lines = [
        MARKER,
        "## 🛡️ AI Security Review Bot Report",
        "",
        f"**Summary:** {len(posted)} active issue(s) found "
        f"({counts['CRITICAL']} critical, {counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['LOW']} low) | "
        f"{len(suppressed)} suppressed as false alarms | "
        f"Scan time: {scan_seconds:.2f}s | "
        f"AI Triage: {'Enabled' if ai_used else 'Disabled'}",
        ""
    ]

    if not posted:
        lines.append("### ✅ No security issues found")
        lines.append("No critical, high, or medium security vulnerabilities were detected in this change. Great job! 🎉")
    else:
        sorted_posted = sorted(posted, key=lambda f: severity_rank(f.severity), reverse=True)
        for f in sorted_posted:
            badge = SEVERITY_BADGES.get(f.severity.upper(), f"⚪ **{f.severity}**")
            lines.append(f"### {badge} in `{f.file}` (line {f.line})")
            lines.append(f"**Rule:** `{f.rule_id}` ({f.scanner} scanner)")
            lines.append(f"**Issue:** {f.message}")
            lines.append("")
            if f.snippet:
                lines.append("```python")
                lines.append(f.snippet)
                lines.append("```\n")
            if f.ai:
                lines.append(f"**Explanation:** {f.ai.get('explanation', 'N/A')}")
                lines.append(f"**Risk:** {f.ai.get('risk', 'N/A')}")
                fix = f.ai.get("suggested_fix")
                if fix:
                    lines.append("**Suggested Fix:**\n```python\n" + fix + "\n```")
                lines.append(f"*AI Confidence: {float(f.ai.get('confidence', 0.0)) * 100:.0f}%*")
            lines.append("---\n")

    if suppressed:
        lines.append("<details>")
        lines.append(f"<summary>🔍 View {len(suppressed)} suppressed alert(s) filtered as false alarms</summary>\n")
        for s in suppressed:
            lines.append(f"- **{s.file}:{s.line}** (`{s.rule_id}`): {s.suppress_reason}")
        lines.append("</details>\n")

    lines.append("---\n*🤖 Automated review by AI Security Review Bot. Security suggestions and AI triage may be imperfect; always verify fixes before merging.*")
    return "\n".join(lines)


def write_json(findings: List[Finding], path: str) -> None:
    out_dir = os.path.dirname(path)
    if out_dir: os.makedirs(out_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump([f.model_dump() for f in findings], f, indent=2)