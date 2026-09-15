"""The secret-detection engine: signatures, entropy, and redaction."""

from endon_dataprotection.secrets.redaction import redact
from endon_dataprotection.secrets.scanner import SecretMatch, SecretScanner

__all__ = ["SecretMatch", "SecretScanner", "redact"]
