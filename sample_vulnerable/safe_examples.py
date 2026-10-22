"""
Benign, safe patterns that naive static scanners frequently misclassify as vulnerabilities.
Used to evaluate the AI false-positive filter.
"""
import hashlib
import subprocess


def calculate_cache_fingerprint(file_bytes: bytes) -> str:
    # SAFE: MD5 used purely for non-cryptographic cache key / file deduplication, NOT passwords
    return hashlib.md5(file_bytes).hexdigest()


def list_temporary_directory():
    # SAFE: subprocess executed with an explicit argument list, shell=False, and fixed input
    result = subprocess.run(["ls", "-l", "/tmp"], shell=False, check=True, capture_output=True)
    return result.stdout


def validate_internal_invariants(item_count: int):
    # SAFE: assert used for internal development invariant validation, not access control
    assert item_count >= 0, "Item count cannot be negative"
    return item_count


# SAFE: UI display label, not an actual secret or password credential
PASSWORD_FIELD_LABEL = "Password"