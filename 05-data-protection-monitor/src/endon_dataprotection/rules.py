"""EventBridge patterns for the sources the monitor consumes."""

MACIE_FINDINGS = {
    "source": ["aws.macie"],
    "detail-type": ["Macie Finding"],
}

HEALTH_CREDENTIALS_EXPOSED = {
    "source": ["aws.health"],
    "detail-type": ["AWS Health Event"],
    "detail": {"eventTypeCode": ["AWS_RISK_CREDENTIALS_EXPOSED"]},
}
