from wardline.security.quotas import QuotaTracker


def test_quota_blocks_after_limit_and_sticks() -> None:
    tracker = QuotaTracker(limit=3)
    assert tracker.allow("client1") is True
    assert tracker.allow("client1") is True
    assert tracker.allow("client1") is True
    assert tracker.allow("client1") is False
    assert tracker.allow("client1") is False
    assert tracker.used("client1") == 3


def test_quota_is_per_client() -> None:
    tracker = QuotaTracker(limit=2)
    assert tracker.allow("client1") is True
    assert tracker.allow("client1") is True
    assert tracker.allow("client1") is False

    assert tracker.allow("client2") is True
    assert tracker.allow("client2") is True
    assert tracker.allow("client2") is False
