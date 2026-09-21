"""A representative snapshot of the whole platform, for the offline demo and default view.

These are the findings and incidents the other seven projects actually produce, hand-built so
the SOC can be seen end-to-end with no AWS account: a GuardDuty-driven containment (Project 1),
an IAM escalation path (Project 2), a public bucket (Project 3) that Project 1 auto-closed, a
forensics capture (Project 4), and an exposed secret (Project 5). The data uses the real
``endon_core`` contracts, so what the demo shows is exactly what a live store would.
"""

from __future__ import annotations

from endon_core.findings import Domain, Finding, Resource, Severity
from endon_core.incidents import (
    ActionKind,
    ActionRecord,
    ActionStatus,
    Incident,
    IncidentStatus,
    TimelineEntry,
)
from endon_core.store import (
    FindingStore,
    IncidentStore,
    InMemoryFindingStore,
    InMemoryIncidentStore,
)

ACCOUNT = "123456789012"
REGION = "us-east-1"


def _findings() -> list[Finding]:
    return [
        Finding(
            source="endon.detection",
            type="UnauthorizedAccess:IAMUser/MaliciousIPCaller",
            title="Access key used from a known-malicious IP",
            severity=Severity.CRITICAL,
            account_id=ACCOUNT,
            region=REGION,
            domain=Domain.INCIDENT_RESPONSE,
            resources=[Resource(type="AwsIamAccessKey", id="AKIAEXAMPLE0001")],
            description="GuardDuty flagged the CI deploy user's access key calling from a Tor exit node.",
            created_at="2026-09-21T09:31:04.000Z",
            updated_at="2026-09-21T09:31:04.000Z",
        ),
        Finding(
            source="endon.iam-analyzer",
            type="IAM:Role/PrivilegeEscalationPath",
            title="Role can escalate to admin via iam:PassRole + lambda:CreateFunction",
            severity=Severity.HIGH,
            account_id=ACCOUNT,
            region=REGION,
            domain=Domain.IAM,
            resources=[
                Resource(type="AwsIamRole", id="arn:aws:iam::123456789012:role/build-runner")
            ],
            description="build-runner can pass a privileged role to a Lambda it creates, reaching admin.",
            created_at="2026-09-21T09:42:10.000Z",
            updated_at="2026-09-21T09:42:10.000Z",
        ),
        Finding(
            source="endon.posture-scanner",
            type="Posture:S3/BucketPubliclyAccessible",
            title="S3 bucket is publicly readable",
            severity=Severity.HIGH,
            account_id=ACCOUNT,
            region=REGION,
            domain=Domain.DATA_PROTECTION,
            resources=[Resource(type="AwsS3Bucket", id="acme-prod-exports")],
            description="Block Public Access is off and a bucket policy allows anonymous s3:GetObject.",
            created_at="2026-09-21T08:17:55.000Z",
            updated_at="2026-09-21T08:17:55.000Z",
        ),
        Finding(
            source="endon.data-protection",
            type="DataProtection:Lambda/HardcodedSecret",
            title="Hardcoded credential in a Lambda environment variable",
            severity=Severity.MEDIUM,
            account_id=ACCOUNT,
            region=REGION,
            domain=Domain.DATA_PROTECTION,
            resources=[Resource(type="AwsLambdaFunction", id="invoice-webhook")],
            description="A high-entropy value matching a Stripe secret key was found in DB_PASSWORD.",
            created_at="2026-09-21T07:05:31.000Z",
            updated_at="2026-09-21T07:05:31.000Z",
        ),
        Finding(
            source="endon.posture-scanner",
            type="Posture:EC2/UnrestrictedSSH",
            title="Security group allows SSH from 0.0.0.0/0",
            severity=Severity.MEDIUM,
            account_id=ACCOUNT,
            region=REGION,
            domain=Domain.INFRASTRUCTURE,
            resources=[Resource(type="AwsEc2SecurityGroup", id="sg-0af17e2c9bd3")],
            created_at="2026-09-20T22:48:00.000Z",
            updated_at="2026-09-20T22:48:00.000Z",
        ),
        Finding(
            source="endon.iam-analyzer",
            type="IAM:User/UnusedAccessKey",
            title="Access key unused for 214 days",
            severity=Severity.LOW,
            account_id=ACCOUNT,
            region=REGION,
            domain=Domain.IAM,
            resources=[Resource(type="AwsIamAccessKey", id="AKIAEXAMPLE0002")],
            created_at="2026-09-19T12:00:00.000Z",
            updated_at="2026-09-19T12:00:00.000Z",
        ),
    ]


def _incidents(findings: list[Finding]) -> list[Incident]:
    key_finding, escalation, public_bucket = findings[0], findings[1], findings[2]

    contained = Incident(
        incident_id=Incident.id_for(key_finding),
        finding=key_finding,
        playbook="compromised-iam-user",
        opened_at="2026-09-21T09:31:05.000Z",
        detected_at="2026-09-21T09:31:04.000Z",
        status=IncidentStatus.CONTAINED,
        contained_at="2026-09-21T09:31:23.000Z",
        actions=[
            ActionRecord(
                action="deactivate-access-key",
                kind=ActionKind.CONTAIN,
                target="AKIAEXAMPLE0001",
                status=ActionStatus.SUCCEEDED,
                message="Access key deactivated",
                at="2026-09-21T09:31:12.000Z",
            ),
            ActionRecord(
                action="request-forensics",
                kind=ActionKind.EVIDENCE,
                target="i-0abc123def",
                status=ActionStatus.SUCCEEDED,
                message="Forensics requested for the associated instance",
                at="2026-09-21T09:31:18.000Z",
            ),
            ActionRecord(
                action="notify",
                kind=ActionKind.REPORT,
                target="endon-alerts",
                status=ActionStatus.SUCCEEDED,
                at="2026-09-21T09:31:23.000Z",
            ),
        ],
        timeline=[
            TimelineEntry("2026-09-21T09:31:05.000Z", "opened", "compromised-iam-user playbook"),
            TimelineEntry("2026-09-21T09:31:12.000Z", "contained", "Deactivated access key"),
            TimelineEntry(
                "2026-09-21T09:31:18.000Z", "evidence", "Forensics requested (Project 4)"
            ),
            TimelineEntry("2026-09-21T09:31:23.000Z", "reported", "Alert sent"),
        ],
    )

    monitoring = Incident(
        incident_id=Incident.id_for(escalation),
        finding=escalation,
        playbook="iam-risk-review",
        opened_at="2026-09-21T09:42:11.000Z",
        detected_at="2026-09-21T09:42:10.000Z",
        status=IncidentStatus.MONITORING,
        actions=[
            ActionRecord(
                action="notify",
                kind=ActionKind.REPORT,
                target="endon-alerts",
                status=ActionStatus.SUCCEEDED,
                message="IAM findings are reviewed, never auto-remediated",
                at="2026-09-21T09:42:12.000Z",
            )
        ],
        timeline=[
            TimelineEntry("2026-09-21T09:42:11.000Z", "opened", "iam-risk-review playbook"),
            TimelineEntry("2026-09-21T09:42:12.000Z", "monitoring", "Queued for human review"),
        ],
    )

    remediated = Incident(
        incident_id=Incident.id_for(public_bucket),
        finding=public_bucket,
        playbook="s3-public-exposure",
        opened_at="2026-09-21T08:17:56.000Z",
        detected_at="2026-09-21T08:17:55.000Z",
        status=IncidentStatus.CONTAINED,
        contained_at="2026-09-21T08:18:09.000Z",
        actions=[
            ActionRecord(
                action="enable-block-public-access",
                kind=ActionKind.REMEDIATE,
                target="acme-prod-exports",
                status=ActionStatus.SUCCEEDED,
                message="Block Public Access re-enabled on the bucket",
                at="2026-09-21T08:18:09.000Z",
            )
        ],
        timeline=[
            TimelineEntry("2026-09-21T08:17:56.000Z", "opened", "s3-public-exposure playbook"),
            TimelineEntry(
                "2026-09-21T08:18:09.000Z", "contained", "Re-enabled Block Public Access"
            ),
        ],
    )

    return [contained, monitoring, remediated]


def seed_stores() -> tuple[IncidentStore, FindingStore]:
    """Return in-memory stores populated with the representative platform snapshot."""
    findings = _findings()
    finding_store = InMemoryFindingStore()
    for finding in findings:
        finding_store.save(finding)

    incident_store = InMemoryIncidentStore()
    for incident in _incidents(findings):
        incident_store.save(incident)

    return incident_store, finding_store
