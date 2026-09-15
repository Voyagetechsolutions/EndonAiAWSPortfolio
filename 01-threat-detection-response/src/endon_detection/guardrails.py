"""Safety checks that run before any action changes a resource.

Automated response is only trustworthy if it cannot be turned against the
environment it protects. Guardrails stop the engine from touching:

* resources tagged as protected (break-glass users, intentionally public buckets)
* AWS service-linked and reserved (SSO) roles
* the responder's own role, so a crafted finding cannot disable the responder

If a check cannot be completed, the engine fails safe and does not act.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from endon_core.aws import ClientFactory, error_code
from endon_core.findings import Resource
from endon_detection.actions.resources import bucket_name, instance_id, role_name, user_name

_NOT_FOUND = {
    "NoSuchEntity",
    "InvalidInstanceID.NotFound",
    "InvalidInstanceID.Malformed",
    "NoSuchBucket",
}
_AWS_MANAGED_ROLE_PATHS = ("/aws-service-role/", "/aws-reserved/")
_TRUE_VALUES = {"true", "yes", "1"}


class Guardrails:
    def __init__(
        self,
        clients: ClientFactory,
        protected_tag_key: str = "endon:protected",
        responder_role_names: frozenset[str] = frozenset(),
    ) -> None:
        self.clients = clients
        self.protected_tag_key = protected_tag_key
        self.responder_role_names = responder_role_names

    def check(self, resource: Resource) -> str | None:
        """Return why the resource must not be changed, or None if it is safe to act on."""
        checker = {
            "AwsIamUser": self._iam_user,
            "AwsIamRole": self._iam_role,
            "AwsEc2Instance": self._ec2_instance,
            "AwsS3Bucket": self._s3_bucket,
        }.get(resource.type)
        if checker is None:
            return None
        try:
            return checker(resource)
        except ClientError as exc:
            code = error_code(exc)
            if code in _NOT_FOUND:
                return None  # nothing to protect; the action will report the missing resource
            return f"could not verify the resource is safe to change ({code or 'unknown error'})"

    def _iam_user(self, resource: Resource) -> str | None:
        tags = self.clients("iam").list_user_tags(UserName=user_name(resource))["Tags"]
        return self._protected(tags)

    def _iam_role(self, resource: Resource) -> str | None:
        name = role_name(resource)
        if name in self.responder_role_names:
            return "target is the Endon responder's own role"
        iam = self.clients("iam")
        role = iam.get_role(RoleName=name)["Role"]
        if role.get("Path", "/").startswith(_AWS_MANAGED_ROLE_PATHS):
            return "target is an AWS service-linked or reserved role"
        return self._protected(iam.list_role_tags(RoleName=name)["Tags"])

    def _ec2_instance(self, resource: Resource) -> str | None:
        reservations = self.clients("ec2").describe_instances(InstanceIds=[instance_id(resource)])
        tags = [
            tag
            for reservation in reservations["Reservations"]
            for instance in reservation["Instances"]
            for tag in instance.get("Tags", [])
        ]
        return self._protected(tags)

    def _s3_bucket(self, resource: Resource) -> str | None:
        try:
            tags = self.clients("s3").get_bucket_tagging(Bucket=bucket_name(resource))["TagSet"]
        except ClientError as exc:
            if error_code(exc) == "NoSuchTagSet":
                return None
            raise
        return self._protected(tags)

    def _protected(self, tags: list[dict[str, Any]]) -> str | None:
        for tag in tags:
            if (
                tag["Key"] == self.protected_tag_key
                and tag["Value"].strip().lower() in _TRUE_VALUES
            ):
                return f"resource is tagged {self.protected_tag_key}={tag['Value']}"
        return None
