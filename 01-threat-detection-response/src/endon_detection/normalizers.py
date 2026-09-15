"""Convert EventBridge events from each detection source into Endon findings."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from endon_core.events import FINDING_PRODUCERS, DetailType
from endon_core.findings import Domain, Finding, Resource, Severity
from endon_core.timeutil import isoformat, utc_now


def normalize_event(event: Mapping[str, Any]) -> list[Finding]:
    source = event.get("source", "")
    detail_type = event.get("detail-type", "")
    detail = event.get("detail") or {}

    if source == "aws.guardduty" and detail_type == "GuardDuty Finding":
        finding = from_guardduty(detail)
        return [finding] if finding else []

    if source == "aws.securityhub" and detail_type == "Security Hub Findings - Imported":
        return [f for raw in detail.get("findings", []) if (f := from_security_hub(raw))]

    if source in FINDING_PRODUCERS and detail_type == DetailType.FINDING:
        finding = Finding.from_dict(detail["finding"])
        # Trust the envelope, not the payload: a publisher on the Endon bus must not
        # be able to pass its finding off as a GuardDuty detection. EventBridge
        # rejects PutEvents calls that use an "aws." source, so the envelope is reliable.
        finding.source = source
        return [finding]

    return []


def from_guardduty(detail: Mapping[str, Any]) -> Finding | None:
    service = detail.get("service") or {}
    if service.get("archived"):
        return None

    account_id = detail["accountId"]
    region = detail["region"]
    partition = detail.get("partition", "aws")
    resource = detail.get("resource") or {}
    action = service.get("action") or {}

    tags = {
        "resourceType": resource.get("resourceType"),
        "resourceRole": service.get("resourceRole"),
        "actionType": action.get("actionType"),
        "api": (action.get("awsApiCallAction") or {}).get("api"),
        "remoteIp": _remote_ip(action),
        "count": str(service.get("count", 1)),
        "sample": "true" if _is_sample(service) else None,
    }
    now = isoformat(utc_now())
    return Finding(
        id=detail["id"],
        source="aws.guardduty",
        type=detail["type"],
        title=detail.get("title") or detail["type"],
        description=detail.get("description", ""),
        severity=Severity.from_guardduty(float(detail.get("severity", 0))),
        account_id=account_id,
        region=region,
        resources=_guardduty_resources(resource, account_id, region, partition),
        created_at=detail.get("createdAt") or now,
        updated_at=detail.get("updatedAt") or now,
        first_observed_at=service.get("eventFirstSeen"),
        domain=Domain.DETECTION,
        tags={k: v for k, v in tags.items() if v},
        raw=dict(detail),
    )


def from_security_hub(raw: Mapping[str, Any]) -> Finding | None:
    product_fields = raw.get("ProductFields") or {}
    product_name = raw.get("ProductName") or product_fields.get("aws/securityhub/ProductName", "")

    # GuardDuty findings are consumed from GuardDuty's own events; handling the
    # Security Hub copy as well would open duplicate incidents.
    if product_name == "GuardDuty":
        return None
    # Only AWS-integrated products. Custom findings (including Endon's own exports)
    # can be imported by anyone with securityhub:BatchImportFindings.
    if ":product/aws/" not in raw.get("ProductArn", ""):
        return None
    if raw.get("RecordState") == "ARCHIVED":
        return None
    if (raw.get("Workflow") or {}).get("Status") in ("RESOLVED", "SUPPRESSED"):
        return None
    compliance = raw.get("Compliance") or {}
    if compliance.get("Status") == "PASSED":
        return None

    control_id = compliance.get("SecurityControlId")
    finding_type = (
        f"SecurityHub:{control_id}" if control_id else (raw.get("Types") or ["SecurityHub"])[0]
    )
    now = isoformat(utc_now())
    return Finding(
        id=raw["Id"],
        source="aws.securityhub",
        type=finding_type,
        title=raw.get("Title", finding_type),
        description=raw.get("Description", ""),
        severity=Severity((raw.get("Severity") or {}).get("Label", "INFORMATIONAL")),
        account_id=raw["AwsAccountId"],
        region=raw.get("Region", ""),
        resources=[
            Resource(
                type=r["Type"], id=r["Id"], region=r.get("Region"), details=r.get("Details") or {}
            )
            for r in raw.get("Resources", [])
        ],
        remediation=((raw.get("Remediation") or {}).get("Recommendation") or {}).get("Text", ""),
        created_at=raw.get("CreatedAt") or now,
        updated_at=raw.get("UpdatedAt") or now,
        first_observed_at=raw.get("FirstObservedAt"),
        control_id=control_id,
        domain=Domain.DETECTION,
        tags={"productName": product_name} if product_name else {},
        raw=dict(raw),
    )


def _guardduty_resources(
    resource: Mapping[str, Any], account_id: str, region: str, partition: str
) -> list[Resource]:
    resources: list[Resource] = []

    key = resource.get("accessKeyDetails") or {}
    user_type, user_name = key.get("userType"), key.get("userName")
    if user_type == "IAMUser" and user_name:
        resources.append(
            Resource(
                "AwsIamUser",
                f"arn:{partition}:iam::{account_id}:user/{user_name}",
                details={"userName": user_name, "principalId": key.get("principalId")},
            )
        )
        if key.get("accessKeyId"):
            resources.append(
                Resource("AwsIamAccessKey", key["accessKeyId"], details={"userName": user_name})
            )
    elif user_type == "AssumedRole" and user_name:
        resources.append(
            Resource(
                "AwsIamRole",
                f"arn:{partition}:iam::{account_id}:role/{user_name}",
                details={
                    "roleName": user_name,
                    "principalId": key.get("principalId"),
                    "accessKeyId": key.get("accessKeyId"),
                },
            )
        )
    elif user_type == "Root":
        resources.append(
            Resource("AwsAccount", f"AWS::::Account:{account_id}", details={"principal": "root"})
        )

    instance = resource.get("instanceDetails") or {}
    if instance.get("instanceId"):
        interfaces = instance.get("networkInterfaces") or []
        resources.append(
            Resource(
                "AwsEc2Instance",
                f"arn:{partition}:ec2:{region}:{account_id}:instance/{instance['instanceId']}",
                region=region,
                details={
                    "instanceId": instance["instanceId"],
                    "vpcId": interfaces[0].get("vpcId") if interfaces else None,
                    "iamInstanceProfileArn": (instance.get("iamInstanceProfile") or {}).get("arn"),
                },
            )
        )

    for bucket in resource.get("s3BucketDetails") or []:
        name = bucket.get("name")
        if name:
            resources.append(
                Resource(
                    "AwsS3Bucket",
                    bucket.get("arn") or f"arn:{partition}:s3:::{name}",
                    details={"bucketName": name},
                )
            )
    return resources


def _is_sample(service: Mapping[str, Any]) -> bool:
    info = service.get("additionalInfo") or {}
    if info.get("sample") is True:
        return True
    value = info.get("value")
    if isinstance(value, str):
        try:
            return json.loads(value).get("sample") is True
        except (ValueError, AttributeError):
            return False
    return False


def _remote_ip(action: Mapping[str, Any]) -> str | None:
    for detail in action.values():
        if isinstance(detail, Mapping):
            ip = (detail.get("remoteIpDetails") or {}).get("ipAddressV4")
            if ip:
                return ip
    return None
