"""Builders for GuardDuty findings as EventBridge delivers them.

The event structure matches what GuardDuty publishes, so the same events drive
unit tests, the offline attack replay, and manual test invocations of the Lambda.
Default severities match GuardDuty's documented values for each finding type.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from endon_core.timeutil import isoformat, utc_now

DETECTOR_ID = "12abc34d567e8fa901bc2d34e56789f0"


def guardduty_event(
    finding_type: str,
    *,
    account_id: str,
    region: str,
    resource: dict[str, Any],
    severity: float,
    title: str,
    description: str = "",
    resource_role: str = "TARGET",
    action: dict[str, Any] | None = None,
    sample: bool = False,
    count: int = 1,
    observed_at: str | None = None,
) -> dict[str, Any]:
    now = observed_at or isoformat(utc_now(), "seconds")
    basis = f"{account_id}|{finding_type}|{json.dumps(resource, sort_keys=True)}"
    finding_id = hashlib.sha256(basis.encode()).hexdigest()[:32]
    return {
        "version": "0",
        "id": str(uuid.uuid4()),
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "account": account_id,
        "time": now,
        "region": region,
        "resources": [],
        "detail": {
            "schemaVersion": "2.0",
            "accountId": account_id,
            "region": region,
            "partition": "aws",
            "id": finding_id,
            "arn": f"arn:aws:guardduty:{region}:{account_id}:detector/{DETECTOR_ID}/finding/{finding_id}",
            "type": finding_type,
            "resource": resource,
            "service": {
                "serviceName": "guardduty",
                "detectorId": DETECTOR_ID,
                "action": action or {},
                "resourceRole": resource_role,
                "additionalInfo": {
                    "value": json.dumps({"sample": True}) if sample else "{}",
                    "type": "default",
                },
                "eventFirstSeen": now,
                "eventLastSeen": now,
                "archived": False,
                "count": count,
            },
            "severity": severity,
            "createdAt": now,
            "updatedAt": now,
            "title": title,
            "description": description or title,
        },
    }


def api_call_action(api: str, service: str, ip: str = "198.51.100.23") -> dict[str, Any]:
    return {
        "actionType": "AWS_API_CALL",
        "awsApiCallAction": {
            "api": api,
            "serviceName": service,
            "callerType": "Remote IP",
            "remoteIpDetails": {"ipAddressV4": ip, "organization": {"asnOrg": "Example Hosting"}},
        },
    }


def access_key_resource(
    user_name: str,
    access_key_id: str,
    *,
    user_type: str = "IAMUser",
    principal_id: str = "AIDAEXAMPLEPRINCIPAL",
    instance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resource: dict[str, Any] = {
        "resourceType": "AccessKey",
        "accessKeyDetails": {
            "accessKeyId": access_key_id,
            "principalId": principal_id,
            "userName": user_name,
            "userType": user_type,
        },
    }
    if instance:
        resource["instanceDetails"] = instance["instanceDetails"]
    return resource


def instance_resource(
    instance_id: str,
    *,
    vpc_id: str,
    subnet_id: str,
    network_interface_id: str,
    security_group_ids: list[str],
    instance_type: str = "t3.micro",
    iam_instance_profile_arn: str | None = None,
) -> dict[str, Any]:
    details: dict[str, Any] = {
        "instanceId": instance_id,
        "instanceType": instance_type,
        "instanceState": "running",
        "networkInterfaces": [
            {
                "networkInterfaceId": network_interface_id,
                "vpcId": vpc_id,
                "subnetId": subnet_id,
                "securityGroups": [{"groupId": g} for g in security_group_ids],
            }
        ],
        "tags": [],
    }
    if iam_instance_profile_arn:
        details["iamInstanceProfile"] = {"arn": iam_instance_profile_arn, "id": "AIPAEXAMPLE"}
    return {"resourceType": "Instance", "instanceDetails": details}


def s3_bucket_resource(
    bucket_name: str, *, access_key: dict[str, Any] | None = None
) -> dict[str, Any]:
    resource: dict[str, Any] = {
        "resourceType": "S3Bucket",
        "s3BucketDetails": [
            {"arn": f"arn:aws:s3:::{bucket_name}", "name": bucket_name, "type": "Destination"}
        ],
    }
    if access_key:
        resource["accessKeyDetails"] = access_key["accessKeyDetails"]
    return resource


# --- Attack scenarios -------------------------------------------------------------


def recon_from_malicious_ip(account_id: str, region: str, user: str, key: str) -> dict[str, Any]:
    return guardduty_event(
        "Recon:IAMUser/MaliciousIPCaller.Custom",
        account_id=account_id,
        region=region,
        resource=access_key_resource(user, key),
        severity=5.0,
        title=f"Reconnaissance API calls by {user} from a custom threat list IP",
        action=api_call_action("ListBuckets", "s3.amazonaws.com"),
    )


def api_calls_from_malicious_ip(
    account_id: str, region: str, user: str, key: str
) -> dict[str, Any]:
    return guardduty_event(
        "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
        account_id=account_id,
        region=region,
        resource=access_key_resource(user, key),
        severity=5.0,
        title=f"API AuthorizeSecurityGroupIngress was invoked by {user} from a custom threat list IP",
        action=api_call_action("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com"),
    )


def cloudtrail_logging_disabled(
    account_id: str, region: str, user: str, key: str
) -> dict[str, Any]:
    return guardduty_event(
        "Stealth:IAMUser/CloudTrailLoggingDisabled",
        account_id=account_id,
        region=region,
        resource=access_key_resource(user, key),
        severity=2.0,
        title=f"CloudTrail logging was disabled by {user}",
        action=api_call_action("StopLogging", "cloudtrail.amazonaws.com"),
    )


def s3_block_public_access_disabled(
    account_id: str, region: str, bucket: str, user: str, key: str
) -> dict[str, Any]:
    return guardduty_event(
        "Policy:S3/BucketBlockPublicAccessDisabled",
        account_id=account_id,
        region=region,
        resource=s3_bucket_resource(bucket, access_key=access_key_resource(user, key)),
        severity=2.0,
        title=f"Amazon S3 Block Public Access was disabled for bucket {bucket}",
        action=api_call_action("DeleteBucketPublicAccessBlock", "s3.amazonaws.com"),
    )


def ec2_cryptomining(account_id: str, region: str, instance: dict[str, Any]) -> dict[str, Any]:
    instance_id = instance["instanceDetails"]["instanceId"]
    return guardduty_event(
        "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        account_id=account_id,
        region=region,
        resource=instance,
        severity=8.0,
        resource_role="ACTOR",
        title=f"EC2 instance {instance_id} is querying a domain name associated with cryptocurrency mining",
        action={
            "actionType": "DNS_REQUEST",
            "dnsRequestAction": {"domain": "xmr-pool.example.net", "protocol": "UDP"},
        },
    )


def instance_credential_exfiltration(
    account_id: str, region: str, role_name: str, instance: dict[str, Any]
) -> dict[str, Any]:
    return guardduty_event(
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        account_id=account_id,
        region=region,
        resource=access_key_resource(
            role_name,
            "ASIAEXAMPLESESSIONKEY",
            user_type="AssumedRole",
            principal_id="AROAEXAMPLE:i-session",
            instance=instance,
        ),
        severity=8.0,
        title=f"Credentials for instance role {role_name} used from an external IP address",
        action=api_call_action("ListBuckets", "s3.amazonaws.com"),
    )


def port_probe(account_id: str, region: str, instance: dict[str, Any]) -> dict[str, Any]:
    instance_id = instance["instanceDetails"]["instanceId"]
    return guardduty_event(
        "Recon:EC2/PortProbeUnprotectedPort",
        account_id=account_id,
        region=region,
        resource=instance,
        severity=2.0,
        title=f"Unprotected port on EC2 instance {instance_id} is being probed",
        action={
            "actionType": "PORT_PROBE",
            "portProbeAction": {"portProbeDetails": [{"localPortDetails": {"port": 22}}]},
        },
    )
