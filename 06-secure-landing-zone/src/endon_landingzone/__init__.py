"""Endon AI secure multi-account AWS landing zone.

Governance that sits *above* the workload accounts: an organization structure, a catalog
of Service Control Policy guardrails, and a security baseline. The distinctive piece is the
SCP simulator, which proves the guardrails hold — that even a full administrator in a
workload account cannot turn off logging or detection, operate outside approved regions, or
make data public.
"""

from endon_landingzone.organization import Account, OrgUnit, build_endon_organization
from endon_landingzone.scps import SCP_CATALOG, Scp
from endon_landingzone.simulator import ScpDecision, ScpSimulator

__all__ = [
    "SCP_CATALOG",
    "Account",
    "OrgUnit",
    "Scp",
    "ScpDecision",
    "ScpSimulator",
    "build_endon_organization",
]
