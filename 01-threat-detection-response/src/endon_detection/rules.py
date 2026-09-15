"""EventBridge patterns that route findings to the response engine.

These dictionaries are deployed verbatim by the CDK stack and evaluated by the
local in-memory bus, so what is tested offline is exactly what runs in AWS.
"""

from endon_core.events import FINDING_PRODUCERS, DetailType

GUARDDUTY_FINDINGS = {
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
}

SECURITY_HUB_FINDINGS = {
    "source": ["aws.securityhub"],
    "detail-type": ["Security Hub Findings - Imported"],
    "detail": {
        "findings": {
            "Severity": {"Label": ["HIGH", "CRITICAL"]},
            "Workflow": {"Status": ["NEW"]},
            "RecordState": ["ACTIVE"],
            "ProductName": [{"anything-but": ["GuardDuty"]}],
        }
    },
}

ENDON_FINDINGS = {
    "source": list(FINDING_PRODUCERS),
    "detail-type": [DetailType.FINDING],
}
