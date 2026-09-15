# endon-core

Shared contracts and platform infrastructure for every [Endon AI](../README.md) component.

Components never import each other. They import `endon-core`, and communicate through
events on the Endon security bus. That keeps each project independently deployable
while the platform works as one system.

## What's inside

| Module | Provides |
|---|---|
| `endon_core.findings` | `Finding`, `Resource`, `Severity`, `Domain`; ASFF rendering for Security Hub |
| `endon_core.incidents` | `Incident`, action records, timeline, time-to-contain |
| `endon_core.events` | Event sources and detail types, `EventBridgePublisher`, `InMemoryEventBus`, EventBridge pattern matching |
| `endon_core.store` | DynamoDB and in-memory stores for incidents and findings |
| `endon_core.config` | `Settings` read from environment variables set by CDK |
| `endon_core.aws` | Client factory with adaptive retries, error helpers |
| `infrastructure/platform_stack.py` | KMS key, event bus with archive, tables, alerts topic, Object Lock evidence bucket |
| `infrastructure/lambda_bundle.py` | Builds Lambda packages from the monorepo without Docker |

The only runtime dependency is boto3, which Lambda already provides.

## Publishing a finding from a new component

```python
import boto3

from endon_core.events import DetailType, EventBridgePublisher, Source
from endon_core.findings import Domain, Finding, Resource, Severity

finding = Finding(
    source=Source.POSTURE_SCANNER,
    type="Posture:S3/BucketPubliclyAccessible",
    title="S3 bucket customer-exports is publicly accessible",
    severity=Severity.HIGH,
    account_id="111122223333",
    region="eu-west-1",
    resources=[Resource("AwsS3Bucket", "arn:aws:s3:::customer-exports")],
    control_id="S3-001",
    domain=Domain.DATA_PROTECTION,
    remediation="Enable all four S3 Block Public Access settings.",
)

publisher = EventBridgePublisher("endon-security-bus", boto3.client("events"))
publisher.publish(Source.POSTURE_SCANNER, DetailType.FINDING, {"finding": finding.to_dict()})
```

The response engine picks it up, matches the `s3-public-exposure` playbook and
re-enables Block Public Access. The SOC dashboard shows the resulting incident.
