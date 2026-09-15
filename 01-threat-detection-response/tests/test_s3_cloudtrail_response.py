from detection_testkit import ACCOUNT_ID, REGION
from endon_core.incidents import ActionStatus, IncidentStatus
from endon_detection import samples

BLOCK_ALL = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def test_public_bucket_exposure_is_closed_and_existing_tags_kept(aws, engine, iam_user):
    s3 = aws("s3")
    s3.create_bucket(Bucket="acme-customer-exports")
    s3.put_bucket_tagging(
        Bucket="acme-customer-exports", Tagging={"TagSet": [{"Key": "owner", "Value": "data-team"}]}
    )
    event = samples.s3_block_public_access_disabled(
        ACCOUNT_ID, REGION, "acme-customer-exports", iam_user["name"], iam_user["keys"][0]
    )

    [incident] = engine.handle_event(event)

    assert incident.playbook == "s3-public-exposure"
    assert incident.status is IncidentStatus.CONTAINED
    config = s3.get_public_access_block(Bucket="acme-customer-exports")[
        "PublicAccessBlockConfiguration"
    ]
    assert config == BLOCK_ALL
    tags = {
        t["Key"]: t["Value"]
        for t in s3.get_bucket_tagging(Bucket="acme-customer-exports")["TagSet"]
    }
    assert tags["owner"] == "data-team"
    assert tags["endon:incident-id"] == incident.incident_id


def test_intentionally_public_bucket_is_protected(aws, engine, iam_user):
    s3 = aws("s3")
    s3.create_bucket(Bucket="acme-public-website")
    s3.put_bucket_tagging(
        Bucket="acme-public-website",
        Tagging={"TagSet": [{"Key": "endon:protected", "Value": "true"}]},
    )
    event = samples.s3_block_public_access_disabled(
        ACCOUNT_ID, REGION, "acme-public-website", iam_user["name"], iam_user["keys"][0]
    )

    [incident] = engine.handle_event(event)

    assert incident.status is IncidentStatus.SUPPRESSED


def test_cloudtrail_logging_is_restored(aws, engine, iam_user):
    aws("s3").create_bucket(Bucket="acme-audit-logs")
    cloudtrail = aws("cloudtrail")
    cloudtrail.create_trail(Name="org-audit-trail", S3BucketName="acme-audit-logs")
    cloudtrail.start_logging(Name="org-audit-trail")
    cloudtrail.stop_logging(Name="org-audit-trail")
    event = samples.cloudtrail_logging_disabled(
        ACCOUNT_ID, REGION, iam_user["name"], iam_user["keys"][0]
    )

    [incident] = engine.handle_event(event)

    assert incident.playbook == "logging-tampering"
    assert incident.status is IncidentStatus.CONTAINED
    assert cloudtrail.get_trail_status(Name="org-audit-trail")["IsLogging"] is True

    # GuardDuty rates this finding LOW, below the containment threshold: logging is
    # restored, but a possibly legitimate administrator is not locked out.
    by_action = {a.action: a for a in incident.actions}
    assert by_action["restore_cloudtrail_logging"].status is ActionStatus.SUCCEEDED
    assert by_action["disable_access_keys"].status is ActionStatus.SKIPPED
    keys = aws("iam").list_access_keys(UserName=iam_user["name"])["AccessKeyMetadata"]
    assert {k["Status"] for k in keys} == {"Active"}
