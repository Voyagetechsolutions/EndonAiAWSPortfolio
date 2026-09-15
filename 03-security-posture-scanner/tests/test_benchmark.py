"""The headline benchmark: scan a known-vulnerable environment and measure detection."""

import pytest

from endon_posture.scanner import PostureScanner
from posture_testkit import REGION, build_vulnerable_environment


@pytest.fixture
def scanned(aws):
    manifest = build_vulnerable_environment(aws)
    result = PostureScanner().scan_account(aws, region=REGION)
    return manifest, result


def test_every_planted_misconfiguration_is_detected(scanned):
    manifest, result = scanned
    expected = manifest.expected_control_ids
    found = result.control_ids
    missed = expected - found

    assert missed == set(), f"scanner missed planted controls: {sorted(missed)}"
    # Detection rate against the planted manifest.
    assert len(expected & found) / len(expected) == 1.0


def test_scan_runs_cleanly_across_services(scanned):
    _, result = scanned
    assert result.errors == [], f"checks errored: {result.errors}"
    assert result.score < 40  # a badly misconfigured account scores low


def test_no_findings_on_correctly_configured_resources(scanned):
    manifest, result = scanned
    flagged = {r.id for f in result.findings for r in f.resources}
    for clean in manifest.clean_resource_ids:
        assert clean not in flagged, f"false positive on hardened resource {clean}"


def test_benchmark_covers_many_services(scanned):
    manifest, _ = scanned
    services = {cid.split("-")[0] for cid in manifest.expected_control_ids}
    assert {"S3", "EC2", "RDS", "CT", "KMS", "IAM", "DET"} <= services
    assert len(manifest.expected_control_ids) >= 20
