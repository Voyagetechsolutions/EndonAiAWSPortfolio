"""Generate a least-privilege starting policy from what a principal actually used.

IAM Access Advisor (`service-last-accessed-details`) reports which services a principal
has called and when. The safest replacement for an over-broad policy is one that allows
only the services in recent use; this builds that policy as a concrete, reviewable
starting point, deliberately erring toward "tighten further by hand".
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from endon_core.timeutil import isoformat, utc_now
from endon_iam_analyzer.models import Principal
from endon_iam_analyzer.timeutil import age_in_days


@dataclass
class ServiceUsage:
    service_namespace: str
    last_authenticated: str | None

    def used_within(self, days: int, now) -> bool:
        age = age_in_days(self.last_authenticated, now)
        return age is not None and age <= days


def fetch_service_usage(iam: Any, principal_arn: str) -> list[ServiceUsage]:
    job_id = iam.generate_service_last_accessed_details(Arn=principal_arn)["JobId"]
    for _ in range(30):
        response = iam.get_service_last_accessed_details(JobId=job_id)
        if response["JobStatus"] == "COMPLETED":
            return [
                ServiceUsage(
                    item["ServiceNamespace"],
                    item.get("LastAuthenticated") and isoformat(item["LastAuthenticated"]),
                )
                for item in response.get("ServicesLastAccessed", [])
            ]
        if response["JobStatus"] == "FAILED":
            break
        time.sleep(1)
    return []


def build_least_privilege_policy(
    principal: Principal, usage: list[ServiceUsage], within_days: int = 90, now=None
) -> dict:
    now = now or utc_now()
    services = sorted({u.service_namespace for u in usage if u.used_within(within_days, now)})
    actions = [f"{service}:*" for service in services] or [
        "# no service used in the window; start from an empty policy"
    ]
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EndonLeastPrivilegeStartingPoint",
                "Effect": "Allow",
                "Action": actions,
                "Resource": "*",
            }
        ],
        # Not part of the policy language; a hint for whoever reviews it.
        "_endon_note": (
            f"Generated for {principal.arn} from services used in the last {within_days} days. "
            "Replace each 'service:*' with the specific actions and resources actually needed."
        ),
    }
