"""Endon AI automated EC2 incident response and forensics.

When the Project 1 response engine isolates a compromised EC2 instance, it publishes an
``Endon Forensics Requested`` event. This component consumes it and collects evidence in
order of volatility — without terminating the instance — hashing every artifact and
writing an immutable, timestamped chain-of-custody manifest to the Object Lock evidence
bucket. The point is containment that preserves evidence.
"""

from endon_forensics.engine import ForensicsEngine
from endon_forensics.models import CaseStatus, EvidenceItem, EvidenceStatus, ForensicCase

__all__ = [
    "CaseStatus",
    "EvidenceItem",
    "EvidenceStatus",
    "ForensicCase",
    "ForensicsEngine",
]
