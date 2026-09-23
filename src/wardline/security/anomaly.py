from collections.abc import Callable, Sequence

from wardline.contracts import (
    SEVERITY_RANK,
    Clock,
    SecurityEvent,
    ServiceName,
    Severity,
)
from wardline.incidents.models import Incident


class AnomalyDetector:
    def __init__(
        self,
        *,
        clock: Clock,
        window_seconds: float = 30.0,
        incident_min_severity: Severity = Severity.HIGH,
    ) -> None:
        self._clock = clock
        self._window_seconds = window_seconds
        self._incident_min_severity = incident_min_severity

    def observe(
        self,
        event: SecurityEvent,
        *,
        history: Sequence[SecurityEvent],
        open_incident: Callable[..., Incident | None],
    ) -> list[SecurityEvent]:
        # they TRIGGER it. But anomaly events themselves must not be recursively observed!
        if event.event_type.startswith("anomaly_"):
            return []

        now = self._clock.now()
        # History contains the new event.
        # But wait, rule says "agrupa por source". We just check the rules for `event.source`.
        source = event.source

        window_start = now.timestamp() - self._window_seconds

        # Collect relevant events from history for this source
        source_events = []
        for e in history:
            if e.source == source and e.timestamp.timestamp() >= window_start:
                # Do not count anomaly events themselves towards rules
                if not e.event_type.startswith("anomaly_"):
                    source_events.append(e)

        # Check if we already emitted anomalies for this source in the window
        emitted_anomalies = {
            e.event_type
            for e in history
            if e.source == source
            and e.timestamp.timestamp() >= window_start
            and e.event_type.startswith("anomaly_")
        }

        new_anomalies = []

        def _emit(
            rule_name: str, count: int, severity: Severity, service: ServiceName, simulation: bool
        ) -> None:
            if rule_name in emitted_anomalies:
                return

            anomaly_event = SecurityEvent(
                timestamp=now,
                source=source,
                service=service,
                event_type=rule_name,
                severity=severity,
                simulation=simulation,
                action="detected",
                correlation_id=event.correlation_id,
                details={
                    "count": count,
                    "window_seconds": int(self._window_seconds),
                    "rule": rule_name,
                },
            )
            new_anomalies.append(anomaly_event)

            if SEVERITY_RANK[severity] >= SEVERITY_RANK[self._incident_min_severity]:
                open_incident(
                    source=source,
                    service=service,
                    severity=severity,
                    event_type=rule_name,
                    correlation_id=event.correlation_id,
                    simulation=simulation,
                )

        # Rule: anomaly_rate_abuse
        rate_events = [
            e
            for e in source_events
            if e.event_type in ("security_rate_limited", "simulated_rate_abuse")
        ]
        if len(rate_events) >= 5:
            _emit(
                "anomaly_rate_abuse",
                len(rate_events),
                Severity.MEDIUM,
                _dominant_service(rate_events),
                _is_all_simulation(rate_events),
            )

        # Rule: anomaly_malformed_input
        malformed_events = [e for e in source_events if "invalid" in e.event_type]
        if len(malformed_events) >= 10:
            _emit(
                "anomaly_malformed_input",
                len(malformed_events),
                Severity.LOW,
                _dominant_service(malformed_events),
                _is_all_simulation(malformed_events),
            )

        # Rule: anomaly_connection_pressure
        pressure_events = [
            e
            for e in source_events
            if e.event_type in ("connection_limit", "simulated_connection_pressure")
        ]
        if len(pressure_events) >= 5:
            _emit(
                "anomaly_connection_pressure",
                len(pressure_events),
                Severity.HIGH,
                _dominant_service(pressure_events),
                _is_all_simulation(pressure_events),
            )

        # Rule: anomaly_udp_burst
        udp_events = [
            e
            for e in source_events
            if e.event_type in ("simulated_udp_burst", "datagrams_dropped")
            or (e.service == ServiceName.UDP and e.action == "dropped")
        ]
        if len(udp_events) >= 10:
            _emit(
                "anomaly_udp_burst",
                len(udp_events),
                Severity.MEDIUM,
                _dominant_service(udp_events),
                _is_all_simulation(udp_events),
            )

        # Rule: anomaly_log_volume
        log_volume_events = [e for e in source_events if e.event_type == "security_log_volume"]
        if len(log_volume_events) >= 1:
            _emit(
                "anomaly_log_volume",
                len(log_volume_events),
                Severity.HIGH,
                _dominant_service(log_volume_events),
                _is_all_simulation(log_volume_events),
            )

        return new_anomalies


def _dominant_service(events: list[SecurityEvent]) -> ServiceName:
    if not events:
        return ServiceName.MONITORING
    counts: dict[ServiceName, int] = {}
    for e in events:
        counts[e.service] = counts.get(e.service, 0) + 1
    # Sort by count desc, then by name to ensure stable tie-breaking if needed
    best = sorted(counts.items(), key=lambda x: (-x[1], x[0].value))[0][0]
    return best


def _is_all_simulation(events: list[SecurityEvent]) -> bool:
    if not events:
        return False
    return all(e.simulation for e in events)
