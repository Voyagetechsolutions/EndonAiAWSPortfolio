"""Response actions available to playbooks, looked up by name."""

from endon_detection.actions.base import Action, ActionContext, ActionOutcome, ActionSkipped
from endon_detection.actions.cloudtrail import RestoreCloudTrailLogging
from endon_detection.actions.ec2 import IsolateInstance, RequestForensics, TagForReview
from endon_detection.actions.iam import DisableAccessKeys, QuarantineIamUser, RevokeRoleSessions
from endon_detection.actions.notify import NotifySecurityTeam
from endon_detection.actions.s3 import BlockS3PublicAccess

REGISTRY: dict[str, Action] = {
    action.name: action
    for action in (
        DisableAccessKeys(),
        QuarantineIamUser(),
        RevokeRoleSessions(),
        IsolateInstance(),
        RequestForensics(),
        TagForReview(),
        BlockS3PublicAccess(),
        RestoreCloudTrailLogging(),
        NotifySecurityTeam(),
    )
}

__all__ = ["REGISTRY", "Action", "ActionContext", "ActionOutcome", "ActionSkipped"]
