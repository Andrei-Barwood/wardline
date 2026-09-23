from wardline.security.backpressure import admission_allowed


def test_admission_allowed_under_limit() -> None:
    assert admission_allowed(active=0, limit=10) is True
    assert admission_allowed(active=9, limit=10) is True


def test_admission_denied_at_or_over_limit() -> None:
    assert admission_allowed(active=10, limit=10) is False
    assert admission_allowed(active=11, limit=10) is False
