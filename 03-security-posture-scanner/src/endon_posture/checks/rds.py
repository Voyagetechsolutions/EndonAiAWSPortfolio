"""RDS posture: public accessibility, encryption at rest, backups."""

from __future__ import annotations

from collections.abc import Iterator

from endon_core.findings import Finding, Resource
from endon_posture.checks.base import check
from endon_posture.context import ScanContext


@check("RDS")
def rds_instances(ctx: ScanContext) -> Iterator[Finding]:
    rds = ctx.clients("rds")
    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page.get("DBInstances", []):
            resource = Resource(
                "AwsRdsDbInstance",
                db.get("DBInstanceArn", ""),
                region=ctx.region,
                details={"dbInstanceIdentifier": db.get("DBInstanceIdentifier")},
            )
            if db.get("PubliclyAccessible"):
                yield ctx.finding("RDS-001", resource)
            if not db.get("StorageEncrypted"):
                yield ctx.finding("RDS-002", resource)
            if not db.get("BackupRetentionPeriod"):
                yield ctx.finding("RDS-003", resource)
