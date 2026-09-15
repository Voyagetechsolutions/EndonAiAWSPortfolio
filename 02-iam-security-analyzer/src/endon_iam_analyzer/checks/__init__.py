"""IAM checks. Each check reads the snapshot and yields Endon findings.

Adding a check is one function decorated with ``@check``; the analyzer runs them all.
"""

from endon_iam_analyzer.checks import (  # noqa: F401  (import registers the checks)
    admin,
    credentials,
    escalation_check,
    trust,
    wildcards,
)
from endon_iam_analyzer.checks.base import CHECKS, CheckContext, check

__all__ = ["CHECKS", "CheckContext", "check"]
