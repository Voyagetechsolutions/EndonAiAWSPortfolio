"""Entropy helpers for detecting high-randomness secrets that no signature matches.

A long, high-entropy base64 or hex string assigned to a secret-looking variable is very
likely a key even when it matches no known vendor format. Entropy plus a length gate plus
a placeholder allowlist keeps the false-positive rate low.
"""

from __future__ import annotations

import math
import string

_BASE64 = set(string.ascii_letters + string.digits + "+/=-_")
_HEX = set("0123456789abcdefABCDEF")


def shannon_entropy(value: str) -> float:
    """Bits of Shannon entropy per character."""
    if not value:
        return 0.0
    counts = {ch: value.count(ch) for ch in set(value)}
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def is_high_entropy(value: str, min_len: int = 20) -> bool:
    """Whether the value looks like a random secret (base64 ≥ ~4.0 bits, hex ≥ ~3.0)."""
    value = value.strip()
    if len(value) < min_len:
        return False
    charset = set(value)
    if charset <= _HEX:
        return len(value) >= 32 and shannon_entropy(value) >= 3.0
    if charset <= _BASE64:
        return shannon_entropy(value) >= 4.0
    return False
