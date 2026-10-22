"""
AI triage and mentor explanation layer using Google Gemini API.
Translates raw scanner issues into beginner-friendly explanations, risk assessments,
actionable code fixes, and evaluates whether an alert is a likely false positive.
"""
from __future__ import annotations
import json
import hashlib
import logging
import os
import re
import time
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from models import Finding, severity_rank

logger = logging.getLogger(__name__)
AI_CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai_cache.json")

SECRET_REDACT_PATTERNS = [
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\b(?:ghp|gho|github_pat)_[a-zA-Z0-9_]{20,255}\b",
    r"\bAIza[0-9A-Za-z\-_]{35}\b",
    r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b",
    r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----",
    r"""(?i)\b(?:password|passwd|secret|token|api_key|apikey)\s*[:=]\s*["']([^"']{8,})["']""",
]


def redact_secrets(text: str) -> str:
    sanitized = text
    for pattern in SECRET_REDACT_PATTERNS:
        sanitized = re.sub(pattern, "[HIDDEN_SECRET]", sanitized)
    return sanitized


def get_file_context(file_path: str, center_line: int, window: int = 5) -> str:
    if not os.path.isfile(file_path):
        return ""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        start = max(0, center_line - window - 1)
        end = min(len(lines), center_line + window)
        context_lines = []
        for i in range(start, end):
            num = i + 1
            marker = ">>" if num == center_line else "  "
            context_lines.append(f"{marker} {num:4d} | {lines[i].rstrip()}")
        return "\n".join(context_lines)
    except Exception:
        return ""


class TriageItem(BaseModel):
    index: int
    explanation: str
    risk: str
    suggested_fix: str
    confidence: float = Field(ge=0.0, le=1.0)
    false_positive: bool


class GeminiClient:
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        from google import genai
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY environment variable is not set")
        self.model = model or os.environ.get("GEMINI_MODEL", "gemini-3.1-flash")
        self.client = genai.Client(api_key=self.api_key)

    def generate_json(self, prompt: str) -> str:
        response = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
            config={"response_mime_type": "application/json", "temperature": 0.0}
        )
        return response.text or "[]"


class MockLLM:
    def __init__(self):
        self.last_prompt = ""

    def generate_json(self, prompt: str) -> str:
        self.last_prompt = prompt
        try:
            items = []
            pattern = r"--- FINDING (\d+) ---\nFile: (.*?)\nRule: (.*?)\nSnippet: (.*?)\nMessage: (.*?)\n(?:Related findings for this package:\n.*?\n)?Context:\n(.*?)(?=\n--- FINDING|\Z)"
            matches = list(re.finditer(pattern, prompt, re.DOTALL))
            for m in matches:
                idx = int(m.group(1))
                fname = m.group(2).strip()
                rule = m.group(3).strip()
                snip = m.group(4).strip()
                is_safe = "safe_examples" in fname.lower()
                if is_safe:
                    items.append({
                        "index": idx,
                        "explanation": f"Safe benign code pattern on rule {rule}. Does not introduce security risk.",
                        "risk": "None in this verified context.",
                        "suggested_fix": "# Benign pattern - no change required\n" + snip,
                        "confidence": 0.95,
                        "false_positive": True
                    })
                else:
                    items.append({
                        "index": idx,
                        "explanation": f"Security alert on {rule}. Sensitive inputs or actions should use secure parameters.",
                        "risk": "An attacker could compromise data or execute unauthorized actions.",
                        "suggested_fix": f"# Replace with safe construct:\n# secure_remediation({snip})",
                        "confidence": 0.90,
                        "false_positive": False
                    })
            return json.dumps(items)
        except Exception:
            return "[]"


def triage(findings: List[Finding], llm: Any, min_confidence: float = 0.6) -> List[Finding]:
    if not findings:
        print("AI triaged: 0; cached: 0; not triaged: 0")
        return []

    max_findings = int(os.environ.get("AI_MAX_FINDINGS", "15"))
    delay_seconds = float(os.environ.get("AI_DELAY_SECONDS", "12"))
    if max_findings < 0:
        raise ValueError("AI_MAX_FINDINGS must be zero or greater")
    if delay_seconds < 0:
        raise ValueError("AI_DELAY_SECONDS must be zero or greater")

    cache = _load_ai_cache()
    cached_count = 0
    uncached_findings: List[Finding] = []
    for finding in findings:
        verdict = cache.get(_finding_fingerprint(finding))
        if not (
            isinstance(verdict, dict)
            and isinstance(verdict.get("ai"), dict)
            and isinstance(verdict.get("suppressed"), bool)
        ):
            uncached_findings.append(finding)
        else:
            _apply_verdict(finding, verdict)
            cached_count += 1

    grouped_findings: List[List[Finding]] = []
    dependency_groups: Dict[str, List[Finding]] = {}
    for finding in uncached_findings:
        package_match = re.match(
            r"\s*([a-zA-Z0-9_.-]+)\s*==", finding.snippet
        ) if finding.scanner == "dependency" else None
        if package_match:
            package_name = re.sub(r"[-_.]+", "-", package_match.group(1)).lower()
            if package_name in dependency_groups:
                dependency_groups[package_name].append(finding)
            else:
                group = [finding]
                dependency_groups[package_name] = group
                grouped_findings.append(group)
        else:
            grouped_findings.append([finding])

    grouped_findings.sort(
        key=lambda group: max(severity_rank(f.severity) for f in group),
        reverse=True,
    )
    selected_groups = grouped_findings[:max_findings]
    untriaged_groups = grouped_findings[max_findings:]
    batch_size = 5
    total_batches = (len(selected_groups) + batch_size - 1) // batch_size
    triaged_count = 0
    not_triaged_count = sum(len(group) for group in untriaged_groups)
    for batch_start in range(0, len(selected_groups), batch_size):
        batch_number = batch_start // batch_size + 1
        print(f"AI batch {batch_number}/{total_batches}")
        batch = selected_groups[batch_start:batch_start + batch_size]
        prompt_parts = [
            "You are a friendly, expert security mentor explaining code vulnerabilities to a beginner developer.",
            "Analyze the following list of security scanner alerts. For each finding, determine if it is a real issue or a false positive.",
            "Reply with ONLY a valid JSON list containing one object per finding with: index, explanation, risk, suggested_fix, confidence (0 to 1), false_positive (bool)."
        ]
        for i, group in enumerate(batch):
            f = group[0]
            context = get_file_context(f.file, f.line, window=5)
            related_findings = "\n".join(
                f"- {related.rule_id}: {related.message}"
                for related in group[1:]
            )
            prompt_parts.append(
                f"\n--- FINDING {i} ---\n"
                f"File: {f.file}\nLine: {f.line}\nScanner: {f.scanner}\nRule: {f.rule_id}\nSeverity: {f.severity}\n"
                f"Snippet: {redact_secrets(f.snippet)}\nMessage: {redact_secrets(f.message)}\n"
                f"Related findings for this package:\n{redact_secrets(related_findings)}\n"
                f"Context:\n{redact_secrets(context)}\n"
            )
        full_prompt = "\n".join(prompt_parts)

        parsed_items: Dict[int, TriageItem] = {}
        for parse_attempt in range(2):
            response_text = None
            for retry in range(4):
                try:
                    response_text = llm.generate_json(full_prompt)
                    break
                except Exception as err:
                    if _is_retryable_ai_error(err) and retry < 3:
                        wait_seconds = 5 * (2 ** retry)
                        print(
                            f"Batch {batch_number}/{total_batches} busy, "
                            f"retrying in {wait_seconds}s"
                        )
                        time.sleep(wait_seconds)
                        continue
                    logger.warning(
                        "AI triage request failed for batch %d: %s",
                        batch_number,
                        err,
                    )
                    break
            if response_text is None:
                break
            try:
                raw_json = json.loads(response_text)
                batch_items: Dict[int, TriageItem] = {}
                for obj in raw_json:
                    item = TriageItem(**obj)
                    batch_items[item.index] = item
                parsed_items = batch_items
                break
            except Exception:
                if parse_attempt == 0:
                    time.sleep(0.5)

        for i, group in enumerate(batch):
            f = group[0]
            if i in parsed_items:
                item = parsed_items[i]
                ai_result = {
                    "explanation": item.explanation,
                    "risk": item.risk,
                    "suggested_fix": item.suggested_fix,
                    "confidence": item.confidence,
                    "false_positive": item.false_positive,
                }
                for member in group:
                    verdict = _make_verdict(ai_result, min_confidence)
                    _apply_verdict(member, verdict)
                    cache[_finding_fingerprint(member)] = verdict
                    triaged_count += 1
            else:
                for member in group:
                    _set_untriaged(member)
                    not_triaged_count += 1

        if parsed_items:
            _save_ai_cache(cache)
        if batch_start + batch_size < len(selected_groups) and delay_seconds:
            time.sleep(delay_seconds)

    for group in untriaged_groups:
        for finding in group:
            _set_untriaged(finding)

    print(
        f"AI triaged: {triaged_count}; cached: {cached_count}; "
        f"not triaged: {not_triaged_count}"
    )
    return findings


def _finding_fingerprint(finding: Finding) -> str:
    identity = json.dumps(
        [
            finding.scanner,
            finding.rule_id,
            finding.file,
            finding.line,
            redact_secrets(finding.snippet),
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _load_ai_cache() -> Dict[str, Dict[str, Any]]:
    try:
        with open(AI_CACHE_FILE, "r", encoding="utf-8") as cache_file:
            cache = json.load(cache_file)
        if not isinstance(cache, dict):
            raise ValueError("AI cache root must be a JSON object")
        return cache
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError, ValueError) as err:
        logger.warning("Could not read AI cache %s: %s", AI_CACHE_FILE, err)
        return {}


def _save_ai_cache(cache: Dict[str, Dict[str, Any]]) -> None:
    temporary_path = f"{AI_CACHE_FILE}.tmp"
    try:
        with open(temporary_path, "w", encoding="utf-8") as cache_file:
            json.dump(cache, cache_file, indent=2)
        os.replace(temporary_path, AI_CACHE_FILE)
    except OSError as err:
        logger.warning("Could not save AI cache %s: %s", AI_CACHE_FILE, err)


def _is_retryable_ai_error(error: Exception) -> bool:
    error_text = str(error).upper()
    status_code = getattr(error, "code", None)
    return (
        status_code in (429, 503, "429", "503")
        or "429" in error_text
        or "503" in error_text
        or "RESOURCE_EXHAUSTED" in error_text
        or "UNAVAILABLE" in error_text
    )


def _make_verdict(ai_result: Dict[str, Any], min_confidence: float) -> Dict[str, Any]:
    confidence = float(ai_result["confidence"])
    false_positive = bool(ai_result["false_positive"])
    if false_positive:
        suppress_reason = f"AI classified as false alarm (confidence: {confidence:.2f})"
        suppressed = True
    elif confidence < min_confidence:
        suppress_reason = (
            f"Suppressed due to low AI confidence "
            f"({confidence:.2f} < {min_confidence})"
        )
        suppressed = True
    else:
        suppress_reason = None
        suppressed = False
    return {
        "ai": ai_result,
        "suppressed": suppressed,
        "suppress_reason": suppress_reason,
    }


def _apply_verdict(finding: Finding, verdict: Dict[str, Any]) -> None:
    finding.ai = verdict["ai"].copy()
    finding.suppressed = bool(verdict["suppressed"])
    finding.suppress_reason = verdict.get("suppress_reason")


def _set_untriaged(finding: Finding) -> None:
    finding.ai = {
        "explanation": "AI explanation unavailable",
        "risk": "Manual review recommended.",
        "suggested_fix": "# Review this finding manually.",
        "confidence": 0.0,
        "false_positive": False,
    }
    finding.suppressed = False
    finding.suppress_reason = "AI explanation unavailable"