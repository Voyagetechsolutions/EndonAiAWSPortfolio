"""Turn Amazon Macie findings and AWS Health credential-exposure events into Endon findings.

Macie is the sensitive-data classifier. Its findings tell us *what* categories of sensitive
data are in a bucket (personal, credentials, financial) and whether that bucket is public.
The important escalation is the combination: sensitive data that is *also* publicly
accessible becomes a CRITICAL finding routed to Project 1 for automatic Block Public Access.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from endon_core.findings import Domain, Finding, Resource, Severity
from endon_core.timeutil import isoformat, utc_now

# Macie sensitive-data categories, worst first.
_CATEGORY_SEVERITY = {
    "CREDENTIALS": Severity.HIGH,
    "FINANCIAL_INFORMATION": Severity.HIGH,
    "PERSONAL_INFORMATION": Severity.MEDIUM,
}
_MACIE_LABEL_SEVERITY = {"High": Severity.HIGH, "Medium": Severity.MEDIUM, "Low": Severity.LOW}


def normalize_event(event: Mapping[str, Any]) -> list[Finding]:
    source = event.get("source", "")
    detail_type = event.get("detail-type", "")
    detail = event.get("detail") or {}

    if source == "aws.macie" and detail_type == "Macie Finding":
        finding = from_macie(detail)
        return [finding] if finding else []
    if source == "aws.health" and detail_type == "AWS Health Event":
        return from_health(detail)
    return []


def from_macie(detail: Mapping[str, Any]) -> Finding | None:
    if not str(detail.get("type", "")).startswith("SensitiveData"):
        return None
    resources = detail.get("resourcesAffected") or {}
    bucket = resources.get("s3Bucket") or {}
    bucket_name = bucket.get("name")
    if not bucket_name:
        return None

    account_id = detail.get("accountId", "")
    region = detail.get("region", "")
    categories = _categories(detail)
    is_public = _bucket_is_public(bucket)

    if is_public:
        finding_type = "DataProtection:S3/SensitiveDataPubliclyAccessible"
        severity = Severity.CRITICAL
        title = f"Publicly accessible S3 bucket contains sensitive data: {bucket_name}"
    else:
        finding_type = "DataProtection:S3/SensitiveDataAtRest"
        severity = _severity_from_categories(categories, detail)
        title = f"S3 bucket contains sensitive data: {bucket_name}"

    now = isoformat(utc_now())
    return Finding(
        id=detail.get("id") or f"macie-{bucket_name}",
        source="aws.macie",
        type=finding_type,
        title=title,
        description=(
            f"Amazon Macie classified sensitive data in bucket '{bucket_name}' "
            f"(categories: {', '.join(categories) or 'unspecified'})."
            + (" The bucket is publicly accessible." if is_public else "")
        ),
        severity=severity,
        account_id=account_id,
        region=region,
        resources=[
            Resource(
                "AwsS3Bucket",
                bucket.get("arn") or f"arn:aws:s3:::{bucket_name}",
                details={"bucketName": bucket_name},
            )
        ],
        remediation=(
            "Enable S3 Block Public Access and remove public grants, then review why sensitive "
            "data is stored here; encrypt with SSE-KMS and restrict access."
            if is_public
            else "Encrypt the bucket with SSE-KMS, restrict access to least privilege, and confirm the "
            "data belongs here."
        ),
        control_id="DP-S3-001",
        domain=Domain.DATA_PROTECTION,
        first_observed_at=detail.get("createdAt"),
        created_at=detail.get("createdAt") or now,
        updated_at=detail.get("updatedAt") or now,
        tags={"categories": ",".join(categories), "public": str(is_public).lower()},
        raw=dict(detail),
    )


def from_health(detail: Mapping[str, Any]) -> list[Finding]:
    if detail.get("eventTypeCode") != "AWS_RISK_CREDENTIALS_EXPOSED":
        return []
    account_id = detail.get("accountId", "")
    region = detail.get("region", "us-east-1")
    findings: list[Finding] = []
    for entity in detail.get("affectedEntities") or [{"entityValue": "unknown"}]:
        key_id = entity.get("entityValue", "unknown")
        findings.append(
            Finding(
                id=f"health-cred-exposed-{key_id}",
                source="aws.health",
                type="DataProtection:IAM/CredentialsExposed",
                title=f"AWS access key publicly exposed: {key_id}",
                description=(
                    "AWS Health reports that access key "
                    f"{key_id} has been found publicly exposed (for example, committed to a public "
                    "repository). It must be deactivated and rotated immediately."
                ),
                severity=Severity.CRITICAL,
                account_id=account_id,
                region=region,
                resources=[Resource("AwsIamAccessKey", key_id, details={"accessKeyId": key_id})],
                remediation=(
                    "Deactivate and delete the exposed access key now, rotate any dependent "
                    "credentials, and review CloudTrail for use of the key."
                ),
                control_id="DP-IAM-001",
                domain=Domain.DATA_PROTECTION,
                tags={"eventTypeCode": "AWS_RISK_CREDENTIALS_EXPOSED"},
                raw=dict(detail),
            )
        )
    return findings


def _categories(detail: Mapping[str, Any]) -> list[str]:
    result = ((detail.get("classificationDetails") or {}).get("result")) or {}
    return sorted(
        {item.get("category") for item in result.get("sensitiveData", []) if item.get("category")}
    )


def _severity_from_categories(categories: list[str], detail: Mapping[str, Any]) -> Severity:
    ranked = [_CATEGORY_SEVERITY[c] for c in categories if c in _CATEGORY_SEVERITY]
    if ranked:
        return max(ranked, key=lambda s: s.rank)
    label = (detail.get("severity") or {}).get("description")
    return _MACIE_LABEL_SEVERITY.get(label, Severity.MEDIUM)


def _bucket_is_public(bucket: Mapping[str, Any]) -> bool:
    effective = (bucket.get("publicAccess") or {}).get("effectivePermission")
    return effective == "PUBLIC"
