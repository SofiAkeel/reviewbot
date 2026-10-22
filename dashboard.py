"""
Streamlit interface for launching scans and reviewing saved results.
"""
import json
import os
import subprocess
import sys

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
RESULTS_PATH = os.path.join(PROJECT_ROOT, "results.json")
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

st.set_page_config(page_title="Canary — AI Security Review Bot", page_icon="🐤", layout="wide")
st.title("🐤 Canary — AI Security Review Bot")
st.write("Run a project scan on demand and review its saved findings.")

folder = st.text_input("Project folder", value=PROJECT_ROOT)
use_ai = st.checkbox(
    "Use Gemini for this scan",
    value=bool(os.environ.get("GEMINI_API_KEY")),
    help="The CLI performs AI triage only when you run a new scan.",
)

if st.button("Run new scan", type="primary"):
    if not os.path.isdir(folder):
        st.error(f"Project folder does not exist: {folder}")
    elif use_ai and not os.environ.get("GEMINI_API_KEY"):
        st.error("Gemini is enabled, but GEMINI_API_KEY is not configured.")
    else:
        command = [
            sys.executable,
            os.path.join(PROJECT_ROOT, "cli.py"),
            "scan",
            os.path.abspath(folder),
            "--json",
            RESULTS_PATH,
            "--report",
            os.path.join(PROJECT_ROOT, "report.md"),
        ]
        if not use_ai:
            command.append("--no-ai")
        with st.spinner("Running project scan..."):
            process = subprocess.run(
                command,
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
        if process.stdout:
            st.code(process.stdout)
        if process.returncode not in (0, 1):
            st.error(f"Scan failed with exit code {process.returncode}.")
            if process.stderr:
                st.code(process.stderr)
        else:
            st.success("Scan finished. Showing results.json.")
            if process.stderr:
                st.caption(process.stderr)

if not os.path.isfile(RESULTS_PATH):
    st.info("No results.json found. Run a new scan to create it.")
    st.stop()

try:
    with open(RESULTS_PATH, "r", encoding="utf-8") as results_file:
        findings = json.load(results_file)
    if not isinstance(findings, list):
        raise ValueError("results.json must contain a JSON list of findings")
except (OSError, json.JSONDecodeError, ValueError) as error:
    st.error(f"Could not read {RESULTS_PATH}: {error}")
    st.stop()

active = [finding for finding in findings if not finding.get("suppressed", False)]
suppressed = [finding for finding in findings if finding.get("suppressed", False)]

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total findings", len(findings))
col2.metric("Active", len(active))
col3.metric("Suppressed", len(suppressed))
col4.metric(
    "Noise filtered",
    f"{len(suppressed) / len(findings) * 100:.1f}%" if findings else "0%",
)

severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
severity_counts = {severity: 0 for severity in severity_order}
for finding in active:
    severity = finding.get("severity", "MEDIUM").upper()
    severity_counts[severity] = severity_counts.get(severity, 0) + 1

st.subheader("Findings by severity")
st.bar_chart(
    pd.DataFrame(
        list(severity_counts.items()), columns=["Severity", "Count"]
    ).set_index("Severity")
)

st.subheader("Finding details")
for finding in findings:
    status = "Suppressed" if finding.get("suppressed") else "Active"
    with st.expander(
        f"{status} · {finding.get('severity')} · "
        f"{finding.get('file')}:{finding.get('line')} · {finding.get('rule_id')}"
    ):
        st.write(finding.get("message"))
        if finding.get("snippet"):
            st.code(finding["snippet"], language="python")
        if finding.get("ai"):
            st.markdown(f"**Explanation:** {finding['ai'].get('explanation')}")
            st.markdown(f"**Risk:** {finding['ai'].get('risk')}")
            if finding["ai"].get("suggested_fix"):
                st.markdown("**Suggested fix:**")
                st.code(finding["ai"]["suggested_fix"], language="python")

st.download_button(
    "Download findings as JSON",
    data=json.dumps(findings, indent=2),
    file_name="security-findings.json",
    mime="application/json",
)
