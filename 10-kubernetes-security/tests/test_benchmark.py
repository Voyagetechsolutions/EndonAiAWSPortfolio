"""The benchmark: prove coverage against manifests whose flaws are known in advance."""

from endon_core.findings import Severity
from endon_k8s import controls
from endon_k8s.scanner import scan

POD_CONTROLS = {c.id for c in controls.all_controls() if c.area == "Pod"}
RBAC_CONTROLS = {c.id for c in controls.all_controls() if c.area == "RBAC"}


def test_every_pod_control_fires_on_the_insecure_workload(insecure_pods):
    found = {f.control_id for f in scan(insecure_pods)}
    assert found == POD_CONTROLS, f"pod controls that did not fire: {sorted(POD_CONTROLS - found)}"


def test_the_secure_workload_produces_no_findings(secure_pods):
    assert scan(secure_pods) == []


def test_every_rbac_control_fires_on_the_insecure_rbac(insecure_rbac):
    found = {f.control_id for f in scan(insecure_rbac)}
    assert found >= RBAC_CONTROLS, (
        f"rbac controls that did not fire: {sorted(RBAC_CONTROLS - found)}"
    )


def test_least_privilege_rbac_produces_no_findings(secure_rbac):
    assert scan(secure_rbac) == []


def test_findings_are_platform_findings(insecure_pods):
    sample = scan(insecure_pods)[0]
    assert sample.source == "endon.k8s"
    assert sample.type.startswith("K8s:")
    assert sample.severity is Severity.CRITICAL  # privileged sorts first
    assert sample.to_asff("arn:aws:securityhub:us-east-1:123456789012:product/x/y")["Id"]
