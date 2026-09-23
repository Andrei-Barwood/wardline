from datetime import UTC, datetime, timedelta

from wardline.contracts import SecurityEvent, ServiceName, Severity
from wardline.security.anomaly import AnomalyDetector


class FakeClock:
    def __init__(self, now: datetime):
        self._now = now

    def now(self) -> datetime:
        return self._now


def _event(
    event_type: str,
    source: str,
    now: datetime,
    service: ServiceName = ServiceName.HTTP,
    simulation: bool = False,
    action: str = "recorded",
) -> SecurityEvent:
    return SecurityEvent(
        timestamp=now,
        source=source,
        service=service,
        event_type=event_type,
        severity=Severity.LOW,
        simulation=simulation,
        action=action,
        correlation_id="123",
        details={},
    )


def test_rate_abuse_needs_five():
    now = datetime(2025, 1, 1, tzinfo=UTC)
    detector = AnomalyDetector(clock=FakeClock(now))

    # 4 events
    history = [_event("security_rate_limited", "client1", now) for _ in range(4)]
    opened = []
    anomalies = detector.observe(
        history[-1], history=history, open_incident=lambda **kwargs: opened.append(kwargs)
    )
    assert not anomalies
    assert not opened

    # 5 events
    history = [_event("security_rate_limited", "client1", now) for _ in range(5)]
    anomalies = detector.observe(
        history[-1], history=history, open_incident=lambda **kwargs: opened.append(kwargs)
    )
    assert len(anomalies) == 1
    assert anomalies[0].event_type == "anomaly_rate_abuse"
    assert anomalies[0].severity == Severity.MEDIUM


def test_rate_abuse_does_not_open_incident():
    now = datetime(2025, 1, 1, tzinfo=UTC)
    # Default incident threshold is HIGH, rate abuse is MEDIUM
    detector = AnomalyDetector(clock=FakeClock(now))

    history = [_event("security_rate_limited", "client1", now) for _ in range(5)]
    opened = []
    anomalies = detector.observe(
        history[-1], history=history, open_incident=lambda **kwargs: opened.append(kwargs)
    )
    assert len(anomalies) == 1
    assert anomalies[0].severity == Severity.MEDIUM
    assert not opened  # No incident created


def test_connection_pressure_opens_one_incident():
    now = datetime(2025, 1, 1, tzinfo=UTC)
    detector = AnomalyDetector(clock=FakeClock(now))

    history = [_event("connection_limit", "client1", now) for _ in range(5)]
    opened = []
    anomalies = detector.observe(
        history[-1], history=history, open_incident=lambda **kwargs: opened.append(kwargs)
    )
    assert len(anomalies) == 1
    assert anomalies[0].event_type == "anomaly_connection_pressure"
    assert anomalies[0].severity == Severity.HIGH
    assert len(opened) == 1


def test_second_observation_does_not_duplicate_incident():
    now = datetime(2025, 1, 1, tzinfo=UTC)
    detector = AnomalyDetector(clock=FakeClock(now))

    # If there are 6 events...
    events = [_event("connection_limit", "client1", now) for _ in range(6)]
    anomaly = _event("anomaly_connection_pressure", "client1", now, action="detected")
    history = events + [anomaly]

    opened = []
    anomalies = detector.observe(
        events[-1], history=history, open_incident=lambda **kwargs: opened.append(kwargs)
    )

    # We should not emit the anomaly again
    assert not anomalies
    assert not opened


def test_window_excludes_old_events():
    now = datetime(2025, 1, 1, tzinfo=UTC)
    old = now - timedelta(seconds=31)
    detector = AnomalyDetector(clock=FakeClock(now), window_seconds=30)

    history = [_event("connection_limit", "client1", old) for _ in range(4)]
    history.append(_event("connection_limit", "client1", now))

    opened = []
    anomalies = detector.observe(
        history[-1], history=history, open_incident=lambda **kwargs: opened.append(kwargs)
    )
    assert not anomalies


def test_mixed_simulation_flag_is_false():
    now = datetime(2025, 1, 1, tzinfo=UTC)
    detector = AnomalyDetector(clock=FakeClock(now))

    history = [_event("connection_limit", "client1", now, simulation=True) for _ in range(4)]
    history.append(_event("connection_limit", "client1", now, simulation=False))

    opened = []
    anomalies = detector.observe(
        history[-1], history=history, open_incident=lambda **kwargs: opened.append(kwargs)
    )
    assert len(anomalies) == 1
    assert anomalies[0].simulation is False


def test_all_synthetic_flag_is_true():
    now = datetime(2025, 1, 1, tzinfo=UTC)
    detector = AnomalyDetector(clock=FakeClock(now))

    history = [_event("connection_limit", "client1", now, simulation=True) for _ in range(5)]

    opened = []
    anomalies = detector.observe(
        history[-1], history=history, open_incident=lambda **kwargs: opened.append(kwargs)
    )
    assert len(anomalies) == 1
    assert anomalies[0].simulation is True


def test_log_volume_single_event_opens_incident():
    now = datetime(2025, 1, 1, tzinfo=UTC)
    detector = AnomalyDetector(clock=FakeClock(now))

    history = [_event("security_log_volume", "system", now)]

    opened = []
    anomalies = detector.observe(
        history[-1], history=history, open_incident=lambda **kwargs: opened.append(kwargs)
    )
    assert len(anomalies) == 1
    assert anomalies[0].event_type == "anomaly_log_volume"
    assert anomalies[0].severity == Severity.HIGH
    assert len(opened) == 1


def test_anomaly_events_are_not_observed_recursively():
    now = datetime(2025, 1, 1, tzinfo=UTC)
    detector = AnomalyDetector(clock=FakeClock(now))

    evt = _event("anomaly_log_volume", "system", now)
    history = [evt]

    opened = []
    anomalies = detector.observe(
        history[-1], history=history, open_incident=lambda **kwargs: opened.append(kwargs)
    )
    assert not anomalies
    assert not opened


def test_malformed_rule_is_low_and_no_incident():
    now = datetime(2025, 1, 1, tzinfo=UTC)
    detector = AnomalyDetector(clock=FakeClock(now))

    history = [_event("invalid_message", "client1", now) for _ in range(10)]
    opened = []
    anomalies = detector.observe(
        history[-1], history=history, open_incident=lambda **kwargs: opened.append(kwargs)
    )
    assert len(anomalies) == 1
    assert anomalies[0].event_type == "anomaly_malformed_input"
    assert anomalies[0].severity == Severity.LOW
    assert not opened


def test_udp_rule():
    now = datetime(2025, 1, 1, tzinfo=UTC)
    detector = AnomalyDetector(clock=FakeClock(now))

    # We need 10 dropped datagrams or simulated_udp_burst
    history = [
        _event("message_too_large", "client1", now, service=ServiceName.UDP, action="dropped")
        for _ in range(10)
    ]
    opened = []
    anomalies = detector.observe(
        history[-1], history=history, open_incident=lambda **kwargs: opened.append(kwargs)
    )
    assert len(anomalies) == 1
    assert anomalies[0].event_type == "anomaly_udp_burst"
    assert anomalies[0].severity == Severity.MEDIUM
    assert not opened


def test_detector_failure_does_not_lose_event():
    from wardline.config.settings import Settings
    from wardline.runtime import build_state
    from wardline.security.events import record_event

    state = build_state(Settings(database_url="sqlite:///:memory:"))

    class CrashingDetector:
        def observe(self, *args, **kwargs):
            raise ValueError("boom")

    state.anomaly = CrashingDetector()

    evt = _event("some_event", "system", state.clock.now())
    record_event(state, evt)

    assert len(state.events.list_events()) == 1
