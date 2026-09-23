"""Anomaly detector. The first version records nothing and opens no incidents."""

from wardline.contracts import SecurityEvent


class AnomalyDetector:
    """Observe one structured event and return any derived anomaly events."""

    def observe(self, event: SecurityEvent) -> list[SecurityEvent]:
        del event
        return []
