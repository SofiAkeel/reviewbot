"""
Dependency vulnerability scanner using the Open Source Vulnerabilities (OSV) API.
Audits requirements.txt for known CVEs/advisories and flags unpinned package versions.
"""
from __future__ import annotations
import os
import re
import time
import logging
from typing import List, Dict, Any, Optional
import requests
from models import Finding

logger = logging.getLogger(__name__)
_OSV_CACHE: Dict[str, List[Dict[str, Any]]] = {}


def query_osv(package_name: str, version: str) -> List[Dict[str, Any]]:
    cache_key = f"{package_name}@{version}"
    if cache_key in _OSV_CACHE:
        return _OSV_CACHE[cache_key]

    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {"name": package_name, "ecosystem": "PyPI"},
        "version": version
    }

    for attempt in range(2):
        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulns", [])
                _OSV_CACHE[cache_key] = vulns
                return vulns
            break
        except (requests.RequestException, Exception) as err:
            logger.warning("OSV request error on attempt %d for %s: %s", attempt + 1, cache_key, err)
            if attempt == 0:
                time.sleep(1.0)

    _OSV_CACHE[cache_key] = []
    return []


def extract_fixed_version(vuln_obj: Dict[str, Any]) -> Optional[str]:
    for aff in vuln_obj.get("affected", []):
        for rng in aff.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return str(event["fixed"])
    return None


def map_osv_severity(vuln_obj: Dict[str, Any]) -> str:
    sev_list = vuln_obj.get("severity", [])
    if isinstance(sev_list, list):
        for item in sev_list:
            score = str(item.get("score", "")).upper()
            if "CRITICAL" in score: return "CRITICAL"
            if "HIGH" in score: return "HIGH"
            if "MEDIUM" in score: return "MEDIUM"
            if "LOW" in score: return "LOW"

    db_spec = vuln_obj.get("database_specific", {})
    if isinstance(db_spec, dict):
        db_sev = str(db_spec.get("severity", "")).upper()
        if "CRITICAL" in db_sev: return "CRITICAL"
        if "HIGH" in db_sev: return "HIGH"
        if "MODERATE" in db_sev or "MEDIUM" in db_sev: return "MEDIUM"
        if "LOW" in db_sev: return "LOW"

    return "MEDIUM"


def scan_dependencies(files: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    for file_path in files:
        if os.path.basename(file_path).lower() != "requirements.txt" or not os.path.isfile(file_path):
            continue
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as err:
            logger.warning("Could not read requirements file %s: %s", file_path, err)
            continue

        for line_num, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            line = line.split("#")[0].strip()

            pinned_match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*==\s*([a-zA-Z0-9_\-\.]+)$", line)
            if pinned_match:
                pkg_name, pkg_version = pinned_match.group(1), pinned_match.group(2)
                vulns = query_osv(pkg_name, pkg_version)
                for v in vulns:
                    vuln_id = v.get("id", "VULN-UNKNOWN")
                    summary = v.get("summary") or v.get("details", "Known security vulnerability in package version")
                    if len(summary) > 200:
                        summary = summary[:197] + "..."

                    fixed_ver = extract_fixed_version(v)
                    fix_msg = f" (Fixed in version {fixed_ver})" if fixed_ver else ""
                    findings.append(Finding(
                        scanner="dependency",
                        rule_id=vuln_id,
                        severity=map_osv_severity(v),
                        file=file_path,
                        line=line_num,
                        snippet=f"{pkg_name}=={pkg_version}",
                        message=f"Dependency '{pkg_name}=={pkg_version}' has known vulnerability {vuln_id}: {summary}{fix_msg}"
                    ))
            else:
                unpinned_name = re.split(r"[<>=~!]", line)[0].strip()
                if unpinned_name:
                    findings.append(Finding(
                        scanner="dependency",
                        rule_id="DEP001-UNPINNED",
                        severity="LOW",
                        file=file_path,
                        line=line_num,
                        snippet=line,
                        message=f"Package '{unpinned_name}' is unpinned. Pin the exact version (package==x.y.z) to prevent supply-chain attacks."
                    ))
    return findings