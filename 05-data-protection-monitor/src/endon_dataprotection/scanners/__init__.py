"""Configuration scanners that look for secrets and weak data protection.

Importing this package registers every scanner with the orchestrator.
"""

from endon_dataprotection.scanners import (  # noqa: F401  (imports register the scanners)
    ec2_userdata,
    lambda_env,
    secretsmanager,
)
from endon_dataprotection.scanners.base import SCANNERS, ServiceScanner

__all__ = ["SCANNERS", "ServiceScanner"]
