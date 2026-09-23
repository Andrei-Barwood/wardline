def admission_allowed(*, active: int, limit: int) -> bool:
    """Return True if a new connection is allowed, False if the limit is reached."""
    return active < limit
