"""
GitHub Pull Request commenter script.
Reads report.md and publishes or updates an issue comment on the PR via the GitHub REST API.
Updates the previous comment in-place if the unique bot marker is found.
"""
from __future__ import annotations
import os
import sys
import logging
import requests

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("post_comment")

BOT_MARKER = "<!-- ai-security-review-bot -->"


def main():
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    repository = os.environ.get("GITHUB_REPOSITORY", "").strip()
    pr_number = os.environ.get("PR_NUMBER", "").strip()
    report_path = sys.argv[1] if len(sys.argv) > 1 else "report.md"

    if not all([token, repository, pr_number]):
        logger.error("Missing GITHUB_TOKEN, GITHUB_REPOSITORY, or PR_NUMBER")
        sys.exit(1)

    with open(report_path, "r", encoding="utf-8") as f:
        comment_body = f.read()

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "AI-Security-Review-Bot",
    }
    base_api = f"https://api.github.com/repos/{repository}/issues/{pr_number}/comments"

    existing_comment_id = None
    try:
        response = requests.get(base_api, headers=headers, timeout=15)
        if response.status_code == 200:
            for c in response.json():
                if BOT_MARKER in c.get("body", ""):
                    existing_comment_id = c.get("id")
                    break
    except Exception as err:
        logger.warning("Could not list comments: %s", err)

    if existing_comment_id:
        patch_url = f"https://api.github.com/repos/{repository}/issues/comments/{existing_comment_id}"
        resp = requests.patch(patch_url, json={"body": comment_body}, headers=headers, timeout=15)
        if resp.status_code == 200:
            logger.info("Successfully patched existing comment #%s", existing_comment_id)
        else:
            sys.exit(1)
    else:
        resp = requests.post(base_api, json={"body": comment_body}, headers=headers, timeout=15)
        if resp.status_code == 201:
            logger.info("Created comment #%s", resp.json().get("id"))
        else:
            sys.exit(1)