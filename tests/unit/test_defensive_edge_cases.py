"""Unit tests covering defensive edge cases and boundary conditions."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from wardline.auth.api_keys import parse_dev_api_keys
from wardline.contracts import (
    SEVERITY_RANK,
    ErrorCode,
    IncidentState,
    ServiceName,
    Severity,
)
from wardline.errors import WardlineError
from wardline.incidents.machine import transition
from wardline.incidents.models import Incident
from wardline.monitoring.alerts import select_alerts
from wardline.security.circuit_breaker import CircuitBreaker
from wardline.security.quotas import QuotaTracker
from wardline.security.rate_limit import TokenBucketLimiter
from wardline.security.redaction import redact
from wardline.security.validation import validate_tcp
from wardline.simulation.guard import assert_loopback
from wardline.simulation.scenarios import SimulationRefused
from wardline.storage.cleanup import safe_reset


class _FixedClock:
    def __init__(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now


def test_severity_rank_complete_and_ties() -> None:
    # Full mapping of all severity levels
    assert len(SEVERITY_RANK) == 5
    assert SEVERITY_RANK[Severity.INFO] == 0
    assert SEVERITY_RANK[Severity.LOW] == 1
    assert SEVERITY_RANK[Severity.MEDIUM] == 2
    assert SEVERITY_RANK[Severity.HIGH] == 3
    assert SEVERITY_RANK[Severity.CRITICAL] == 4

    # Ties
    for s in Severity:
        assert SEVERITY_RANK[s] == SEVERITY_RANK[s]
        assert not (SEVERITY_RANK[s] < SEVERITY_RANK[s])

    # Strict ordering
    assert SEVERITY_RANK[Severity.INFO] < SEVERITY_RANK[Severity.LOW]
    assert SEVERITY_RANK[Severity.LOW] < SEVERITY_RANK[Severity.MEDIUM]
    assert SEVERITY_RANK[Severity.MEDIUM] < SEVERITY_RANK[Severity.HIGH]
    assert SEVERITY_RANK[Severity.HIGH] < SEVERITY_RANK[Severity.CRITICAL]


def test_redact_preserves_ints_and_walks_lists() -> None:
    secret = "secret-token-123"
    input_data = {
        "status_code": 200,
        "attempts": 42,
        "items": [
            1,
            2,
            f"Bearer {secret}",
            [3, 4, {"nested_token": secret, "count": 99}],
        ],
        "zero": 0,
    }

    result = redact(input_data, secrets=(secret,))
    # Integers are preserved intact
    assert result["status_code"] == 200
    assert result["attempts"] == 42
    assert result["zero"] == 0
    assert result["items"][0] == 1
    assert result["items"][1] == 2
    assert result["items"][2] == "Bearer [redacted]"
    # Nested lists and dicts are traversed
    assert result["items"][3][0] == 3
    assert result["items"][3][1] == 4
    assert result["items"][3][2]["count"] == 99
    # Key name 'nested_token' matches sensitive fields
    assert result["items"][3][2]["nested_token"] == "[redacted]"


def test_bucket_cost_above_balance_does_not_go_negative() -> None:
    clock = _FixedClock(datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC))
    time_val = 100.0

    def get_time() -> float:
        return time_val

    # Burst of 1 token
    limiter = TokenBucketLimiter(
        clock=clock,  # type: ignore[arg-type]
        get_limits=lambda: (60, 1),
        time_fn=get_time,
    )

    # Attempting cost=2 when burst=1 must return False
    allowed = limiter.allow("client-1", cost=2)
    assert allowed is False

    # Balance must not be negative: immediately trying cost=1 succeeds
    assert limiter.allow("client-1", cost=1) is True

    # Now the 1 token is consumed, next cost=1 fails
    assert limiter.allow("client-1", cost=1) is False


def test_quota_tracker_does_not_increment_on_rejection() -> None:
    tracker = QuotaTracker(limit=2)
    assert tracker.allow("client-quota") is True
    assert tracker.used("client-quota") == 1

    assert tracker.allow("client-quota") is True
    assert tracker.used("client-quota") == 2

    # Reached limit: subsequent allow returns False and does NOT increment
    assert tracker.allow("client-quota") is False
    assert tracker.used("client-quota") == 2

    assert tracker.allow("client-quota") is False
    assert tracker.used("client-quota") == 2


def test_circuit_ignores_failures_outside_window() -> None:
    current_time = 100.0

    def get_time() -> float:
        return current_time

    # Threshold 3 failures within 10.0 seconds window
    cb = CircuitBreaker(
        threshold=3,
        window_seconds=10.0,
        open_seconds=30.0,
        time_fn=get_time,
    )

    # 2 failures at t=100.0
    cb.record_failure()
    cb.record_failure()
    assert cb.state == "closed"
    assert cb.allow() is True

    # Advance time past window (t=115.0)
    current_time = 115.0

    # 1 failure at t=115.0
    cb.record_failure()

    # The 2 earlier failures expired outside the 10s window; circuit must remain closed
    assert cb.state == "closed"
    assert cb.allow() is True


def test_validate_tcp_discards_extra_fields() -> None:
    raw_message = {
        "type": "ping",
        "request_id": "req-safe-1",
        "injected_extra": "should_be_dropped",
        "admin_flag": "true",
        "extra_number": 42,
    }

    cmd = validate_tcp(raw_message)
    assert cmd.type == "ping"
    assert cmd.request_id == "req-safe-1"
    # Extra fields are not present on the returned dataclass
    assert not hasattr(cmd, "injected_extra")
    assert not hasattr(cmd, "admin_flag")
    assert not hasattr(cmd, "extra_number")


def test_duplicate_role_rejected() -> None:
    # Repeated role in API keys must raise validation_error
    with pytest.raises(WardlineError) as exc_info:
        parse_dev_api_keys("viewer:key1,viewer:key2")
    assert exc_info.value.code == ErrorCode.validation_error
    assert "duplicate" in str(exc_info.value).lower()


def test_illegal_transition_does_not_mutate() -> None:
    now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)
    incident = Incident(
        id="inc_000000000001",
        state=IncidentState.DETECTED,
        title="Detected Anomaly",
        source="client-a",
        service=ServiceName.TCP,
        severity=Severity.HIGH,
        correlation_id="00000000-0000-4000-8000-000000000001",
        simulation=False,
        created_at=now,
        updated_at=now,
        actions=(),
    )

    # Illegal action directly from DETECTED to contain (must acknowledge first)
    with pytest.raises(WardlineError) as exc_info:
        transition(incident, "contain", actor="admin-1", now=now)
    assert exc_info.value.code == ErrorCode.invalid_state_transition

    # Original incident is completely unchanged
    assert incident.state == IncidentState.DETECTED
    assert incident.actions == ()
    assert incident.updated_at == now

    # Unknown action
    with pytest.raises(WardlineError) as exc_unknown:
        transition(incident, "arbitrary_action", actor="admin-1", now=now)
    assert exc_unknown.value.code == ErrorCode.invalid_state_transition
    assert incident.state == IncidentState.DETECTED


def test_assert_loopback_rejects_other_loopback_octets() -> None:
    # 127.0.0.1, localhost, and ::1 are allowed
    assert_loopback("127.0.0.1")
    assert_loopback("localhost")
    assert_loopback("::1")

    # 127.0.0.2 is deliberately rejected
    with pytest.raises(SimulationRefused) as exc_info:
        assert_loopback("127.0.0.2")
    assert exc_info.value.refused is True
    assert exc_info.value.reason == "non_loopback_target"

    # Other 127.x.y.z addresses are rejected
    with pytest.raises(SimulationRefused):
        assert_loopback("127.1.2.3")


def test_select_alerts_empty_list() -> None:
    alerts = select_alerts([], min_severity=Severity.INFO)
    assert alerts == []

    alerts_high = select_alerts([], min_severity=Severity.HIGH)
    assert alerts_high == []


def test_safe_reset_rejects_path_escape(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    valid_data = project_root / "data"
    valid_data.mkdir()

    # Traversal escaping outside project_root
    evil_escape = project_root / "data" / ".." / ".." / "etc"
    with pytest.raises(ValueError):
        safe_reset(evil_escape, allowed_root=project_root)

    # Directory named data outside project_root
    other_dir = tmp_path / "outside" / "data"
    other_dir.mkdir(parents=True)
    with pytest.raises(ValueError, match="Path escape detected"):
        safe_reset(other_dir, allowed_root=project_root)

    # Root directory itself
    with pytest.raises(ValueError):
        safe_reset(project_root, allowed_root=project_root)
