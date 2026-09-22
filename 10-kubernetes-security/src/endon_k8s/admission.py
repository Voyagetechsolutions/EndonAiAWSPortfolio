"""A validating admission controller, simulated.

In a real cluster a validating admission webhook (Kyverno, OPA Gatekeeper) sees every pod
*before* it is created and can reject it. This is that decision, in Python: given a workload
object, run the blocking pod-security rules and deny the pod if any fire. It lets the exact
policy the cluster will enforce be unit-tested offline — deny the dangerous pod, admit the
hardened one — and it shares the scanner's rules, so the gate and the audit never disagree.

The Kyverno ClusterPolicies in ``policies/`` are the real, deployable version of the same
intent; this simulator is how you prove they do what you think before they reach a cluster.
"""

from __future__ import annotations

from dataclasses import dataclass

from endon_core.findings import Finding, Severity
from endon_k8s.manifests import K8sObject
from endon_k8s.scanner import scan

# A pod is rejected if it trips any rule at or above this severity.
BLOCK_AT = Severity.HIGH


@dataclass(frozen=True)
class AdmissionResponse:
    allowed: bool
    object_ref: str
    reasons: list[str]

    def message(self) -> str:
        if self.allowed:
            return f"admitted {self.object_ref}"
        return f"denied {self.object_ref}: " + "; ".join(self.reasons)


def review(obj: K8sObject) -> AdmissionResponse:
    """Admit or deny a single workload object, the way a validating webhook would."""
    blocking = [
        f for f in scan([obj]) if f.severity.at_least(BLOCK_AT) and f.type.startswith("K8s:Pod/")
    ]
    return AdmissionResponse(
        allowed=not blocking,
        object_ref=obj.ref,
        reasons=[_reason(f) for f in blocking],
    )


def _reason(finding: Finding) -> str:
    return f"{finding.control_id} {finding.title}"
