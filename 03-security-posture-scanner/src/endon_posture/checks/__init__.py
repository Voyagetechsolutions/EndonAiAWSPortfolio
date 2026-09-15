"""Service checks. Importing this package registers every check with the scanner."""

from endon_posture.checks import (  # noqa: F401  (imports register the checks)
    cloudtrail,
    detection,
    ec2,
    iam,
    kms,
    rds,
    s3,
)
from endon_posture.checks.base import CHECKS, ServiceCheck

__all__ = ["CHECKS", "ServiceCheck"]
