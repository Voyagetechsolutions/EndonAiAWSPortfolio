"""Endon AI data protection and secrets exposure monitor.

Two capabilities, both in the SCS-C03 Data Protection domain:

* a **secret-detection engine** that scans where secrets get left in the open — Lambda
  environment variables, EC2 user data, config — using signatures and entropy, and
  never emits the secret itself (everything is redacted);
* an **event consumer** for Amazon Macie sensitive-data findings and AWS Health
  credential-exposure events, which normalizes them into Endon findings. Sensitive data
  that is also publicly accessible routes to the Project 1 response engine for automatic
  Block Public Access remediation.
"""

from endon_dataprotection.scanner import DataProtectionScanner, ScanResult
from endon_dataprotection.secrets import SecretMatch, SecretScanner

__all__ = ["DataProtectionScanner", "ScanResult", "SecretMatch", "SecretScanner"]
