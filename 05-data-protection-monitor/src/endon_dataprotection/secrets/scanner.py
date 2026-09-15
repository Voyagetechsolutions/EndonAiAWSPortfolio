"""SecretScanner: find secrets in text and in key/value config, always redacted.

Two entry points:

* ``scan_text`` runs the signature set over free text (EC2 user data, a file).
* ``scan_env`` scans a config key/value pair: signatures on the value, plus the
  entropy path when a secret-looking variable name holds a high-entropy value.

Placeholders (``changeme``, ``example``, ``${VAR}``, ``<your-key>``) are suppressed so the
findings that remain are worth acting on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from endon_core.findings import Severity
from endon_dataprotection.secrets.entropy import is_high_entropy, shannon_entropy
from endon_dataprotection.secrets.patterns import PATTERNS, SECRET_NAME_HINTS, SecretPattern
from endon_dataprotection.secrets.redaction import fingerprint, redact

# Values that look secret-shaped but are placeholders, references or obvious non-secrets.
_PLACEHOLDERS = {
    "changeme",
    "change-me",
    "example",
    "password",
    "secret",
    "token",
    "none",
    "null",
    "test",
    "testing",
    "todo",
    "xxx",
    "xxxxxxxx",
    "redacted",
    "placeholder",
    "your-key-here",
    "dummy",
    "fake",
    "sample",
    "notreal",
    "disabled",
}
_PLACEHOLDER_HINTS = (
    "example",
    "changeme",
    "placeholder",
    "your",
    "dummy",
    "sample",
    "<",
    "${",
    "redacted",
)
_REFERENCE = re.compile(r"^(\$\{.*\}|<.*>|\{\{.*\}\}|%\(.*\)s|arn:aws:secretsmanager:)")


@dataclass(frozen=True)
class SecretMatch:
    kind: str
    name: str
    severity: Severity
    location: str
    redacted: str
    fingerprint: str
    confidence: str  # "signature" | "entropy"
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "severity": self.severity.value,
            "location": self.location,
            "redacted": self.redacted,  # never the raw secret
            "fingerprint": self.fingerprint,
            "confidence": self.confidence,
            **({"detail": self.detail} if self.detail else {}),
        }


class SecretScanner:
    def __init__(self, patterns: tuple[SecretPattern, ...] = PATTERNS) -> None:
        self.patterns = patterns

    def scan_text(self, text: str, location: str = "") -> list[SecretMatch]:
        if not text:
            return []
        matches: dict[str, SecretMatch] = {}
        for pattern in self.patterns:
            for found in pattern.regex.finditer(text):
                value = found.group(pattern.group) if pattern.group else found.group(0)
                if not value or self._is_placeholder(value):
                    continue
                match = self._signature_match(pattern, value, location)
                matches.setdefault(match.fingerprint + match.kind, match)
        return list(matches.values())

    def scan_env(self, name: str, value: str, location: str = "") -> list[SecretMatch]:
        if value is None or self._is_placeholder(value):
            return []
        where = f"{location} [{name}]" if location else name
        signature_hits = self.scan_text(value, where)
        if signature_hits:
            return signature_hits
        # No signature: a secret-named variable holding a high-entropy value is very likely a secret.
        if SECRET_NAME_HINTS.search(name) and is_high_entropy(value):
            return [
                SecretMatch(
                    kind="generic-secret",
                    name=f"High-entropy value in secret-named variable '{name}'",
                    severity=Severity.HIGH,
                    location=where,
                    redacted=redact(value),
                    fingerprint=fingerprint(value),
                    confidence="entropy",
                    detail={"entropyBits": round(shannon_entropy(value), 2), "length": len(value)},
                )
            ]
        return []

    def scan_mapping(self, mapping: dict[str, str], location: str = "") -> list[SecretMatch]:
        matches: list[SecretMatch] = []
        for name, value in (mapping or {}).items():
            if isinstance(value, str):
                matches.extend(self.scan_env(name, value, location))
        return matches

    def _signature_match(self, pattern: SecretPattern, value: str, location: str) -> SecretMatch:
        return SecretMatch(
            kind=pattern.kind,
            name=pattern.name,
            severity=pattern.severity,
            location=location,
            redacted=redact(value),
            fingerprint=fingerprint(value),
            confidence="signature",
        )

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        value = value.strip()
        if len(value) < 8:
            return True
        lowered = value.lower()
        if lowered in _PLACEHOLDERS:
            return True
        if _REFERENCE.match(value):
            return True
        if any(hint in lowered for hint in _PLACEHOLDER_HINTS):
            return True
        # A single repeated character (aaaaaaaa, 00000000) is not a real secret.
        return len(set(value)) <= 2
