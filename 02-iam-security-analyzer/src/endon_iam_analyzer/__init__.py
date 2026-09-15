"""Endon AI IAM Least-Privilege & Privilege-Escalation Analyzer.

Reads a complete IAM snapshot for an account, evaluates effective permissions with
a real policy-evaluation engine, and reports over-privilege, dangerous trust
policies, weak credentials and privilege-escalation paths as Endon findings.
"""

from endon_iam_analyzer.analyzer import AnalysisResult, IamAnalyzer
from endon_iam_analyzer.models import AccountSnapshot, Principal
from endon_iam_analyzer.policy import Access, PermissionSet, PolicyDocument, Statement

__all__ = [
    "AccountSnapshot",
    "Access",
    "AnalysisResult",
    "IamAnalyzer",
    "PermissionSet",
    "PolicyDocument",
    "Principal",
    "Statement",
]
