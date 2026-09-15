"""EventBridge pattern that routes forensics requests to the collection engine."""

from endon_core.events import DetailType, Source

FORENSICS_REQUESTED = {
    "source": [Source.DETECTION],
    "detail-type": [DetailType.FORENSICS_REQUESTED],
}
