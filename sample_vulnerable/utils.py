"""
Utility functions containing insecure cryptographic implementations.
"""
import hashlib


def hash_user_password(password: str) -> str:
    # LINE 9: Real Flaw - Broken/Weak Cryptographic Hash (MD5) for passwords (Bandit B324 / B303)
    hasher = hashlib.md5(password.encode("utf-8"))
    return hasher.hexdigest()