"""Cross-project wiring: a public-sensitive-data finding is auto-remediated by Project 1.

Macie finds sensitive data in a bucket that is also public. The data-protection monitor
publishes DataProtection:S3/SensitiveDataPubliclyAccessible; the Project 1 response engine
re-enables S3 Block Public Access automatically — the classifier finds it, the responder
closes it.
"""

from dataprotection_testkit import ACCOUNT_ID, REGION, build_leaky_account, macie_event
from endon_core.config import ResponseMode, Settings
from endon_core.events import InMemoryEventBus, Source
from endon_core.findings import Severity
from endon_core.store import InMemoryIncidentStore
from endon_dataprotection.normalizers import normalize_event
from endon_dataprotection.publish import publish_findings
from endon_dataprotection.scanner import DataProtectionScanner
from endon_detection import rules as detection_rules
from endon_detection.engine import ResponseEngine


def test_public_sensitive_data_is_auto_remediated_by_project1(aws):
    s3 = aws("s3")
    bucket = "acme-customer-exports"
    s3.create_bucket(Bucket=bucket)
    s3.put_bucket_acl(Bucket=bucket, ACL="public-read")

    bus = InMemoryEventBus(account_id=ACCOUNT_ID, region=REGION)
    store = InMemoryIncidentStore()
    engine = ResponseEngine(
        settings=Settings(region=REGION, response_mode=ResponseMode.ENFORCE),
        clients=aws,
        store=store,
        publisher=bus,
    )
    bus.subscribe("endon-findings", detection_rules.ENDON_FINDINGS, engine.handle_event)

    findings = normalize_event(
        macie_event(bucket, public=True, categories=["PERSONAL_INFORMATION"])
    )
    publish_findings(findings, bus, min_severity=Severity.HIGH)

    assert bus.errors == []
    incidents = {i.playbook: i for i in store.list()}
    assert "s3-public-exposure" in incidents
    assert incidents["s3-public-exposure"].status.value == "CONTAINED"
    config = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    assert all(config.values())


def test_secret_findings_route_to_review_not_containment(aws):
    build_leaky_account(aws)
    bus = InMemoryEventBus(account_id=ACCOUNT_ID, region=REGION)
    store = InMemoryIncidentStore()
    engine = ResponseEngine(
        settings=Settings(region=REGION, response_mode=ResponseMode.ENFORCE),
        clients=aws,
        store=store,
        publisher=bus,
    )
    bus.subscribe("endon-findings", detection_rules.ENDON_FINDINGS, engine.handle_event)

    result = DataProtectionScanner().scan_account(aws, region=REGION)
    published = publish_findings(result.findings, bus, min_severity=Severity.HIGH)

    assert published >= 1
    assert all(e["source"] == Source.DATA_PROTECTION for e in bus.events("Endon Finding"))
    # Secrets-in-config are reported for human action, never auto-contained.
    assert all(i.playbook == "triage" for i in store.list())
    assert all(i.status.value == "MONITORING" for i in store.list())
