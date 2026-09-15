"""Restore CloudTrail logging after an attacker turns it off."""

from __future__ import annotations

from endon_core.findings import Resource
from endon_core.incidents import ActionKind
from endon_detection.actions.base import Action, ActionContext, ActionOutcome, ActionSkipped


class RestoreCloudTrailLogging(Action):
    name = "restore_cloudtrail_logging"
    kind = ActionKind.REMEDIATE

    def targets(self, ctx: ActionContext) -> list[Resource]:
        # GuardDuty does not name the trail that was stopped, so every trail homed in
        # the finding's region is checked and any that stopped logging is restarted.
        finding = ctx.finding
        return [
            Resource("AwsAccount", f"AWS::::Account:{finding.account_id}", region=finding.region)
        ]

    def plan(self, target: Resource, ctx: ActionContext) -> str:
        return f"restart logging on any stopped CloudTrail trail in {ctx.finding.region}"

    def execute(self, target: Resource, ctx: ActionContext) -> ActionOutcome:
        cloudtrail = ctx.clients("cloudtrail")
        trails = cloudtrail.describe_trails(includeShadowTrails=False)["trailList"]
        if not trails:
            raise ActionSkipped(f"No CloudTrail trails are homed in {ctx.finding.region}")
        restarted = []
        for trail in trails:
            if not cloudtrail.get_trail_status(Name=trail["TrailARN"]).get("IsLogging"):
                cloudtrail.start_logging(Name=trail["TrailARN"])
                restarted.append(trail["Name"])
        if not restarted:
            raise ActionSkipped("Every trail is already logging")
        return ActionOutcome(
            f"Restarted logging on CloudTrail trail(s): {', '.join(restarted)}",
            {"restartedTrails": restarted},
        )
