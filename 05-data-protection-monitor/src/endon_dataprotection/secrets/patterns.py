"""Signatures for well-known secret formats.

Each pattern names the credential, its severity, and which regex group holds the value to
redact. Signatures catch the high-confidence cases (an AWS key *is* an AWS key); the
entropy path in the scanner catches the rest.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from endon_core.findings import Severity


@dataclass(frozen=True)
class SecretPattern:
    name: str
    kind: str
    regex: re.Pattern
    severity: Severity
    group: int = 0  # regex group holding the secret value (0 = whole match)


def _c(pattern: str) -> re.Pattern:
    return re.compile(pattern)


PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "AWS access key id",
        "aws-access-key",
        _c(r"\b(?:AKIA|ASIA|AIDA|AROA|AKIA)[0-9A-Z]{16}\b"),
        Severity.HIGH,
    ),
    SecretPattern(
        "Private key block",
        "private-key",
        _c(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    SecretPattern("GitHub token", "github-token", _c(r"\bghp_[A-Za-z0-9]{36}\b"), Severity.HIGH),
    SecretPattern(
        "GitHub fine-grained token",
        "github-token",
        _c(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
        Severity.HIGH,
    ),
    SecretPattern(
        "Slack token", "slack-token", _c(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), Severity.HIGH
    ),
    SecretPattern(
        "Stripe live secret key",
        "stripe-key",
        _c(r"\bsk_live_[A-Za-z0-9]{16,}\b"),
        Severity.CRITICAL,
    ),
    SecretPattern(
        "Stripe test secret key", "stripe-key", _c(r"\bsk_test_[A-Za-z0-9]{16,}\b"), Severity.MEDIUM
    ),
    SecretPattern(
        "Google API key", "google-api-key", _c(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.HIGH
    ),
    SecretPattern(
        "SendGrid API key",
        "sendgrid-key",
        _c(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
        Severity.HIGH,
    ),
    SecretPattern("Twilio API key", "twilio-key", _c(r"\bSK[0-9a-fA-F]{32}\b"), Severity.HIGH),
    SecretPattern(
        "JSON Web Token",
        "jwt",
        _c(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
        Severity.MEDIUM,
    ),
    SecretPattern(
        "Database URL with password",
        "db-connection-string",
        _c(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:@\s/]+:([^@\s/]+)@"),
        Severity.HIGH,
        group=1,
    ),
    SecretPattern(
        "AWS secret access key (labelled)",
        "aws-secret-key",
        _c(r"(?i)aws.{0,20}(?:secret|sk).{0,20}[=:\s\"']([A-Za-z0-9/+]{40})\b"),
        Severity.HIGH,
        group=1,
    ),
)

# Variable names that indicate the value is meant to be secret.
SECRET_NAME_HINTS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|"
    r"credential|auth|session[_-]?key|encryption[_-]?key|client[_-]?secret)"
)
