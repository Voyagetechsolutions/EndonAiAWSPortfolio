"""Redaction: a monitor that reports secrets must never store or emit the secret itself.

Every value that leaves the engine is redacted to a short, non-reversible token — a few
edge characters plus a short SHA-256 fingerprint. The fingerprint lets an operator confirm
two findings refer to the same secret (and later confirm it's the one they rotated)
without the finding ever carrying the plaintext.
"""

from __future__ import annotations

import hashlib


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def redact(value: str, keep: int = 3) -> str:
    """Mask a secret to ``AKI…PLE (sha256:1a2b3c4d5e6f)`` form, or fully for short values."""
    value = value.strip()
    fp = f"sha256:{fingerprint(value)}"
    if len(value) <= keep * 2:
        return f"{'*' * len(value)} ({fp})"
    # ASCII ellipsis keeps redacted tokens portable across every console and report encoding.
    return f"{value[:keep]}...{value[-keep:]} ({fp})"
