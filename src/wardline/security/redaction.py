"""Remove laboratory keys and sensitive field names before anything is stored."""

from collections.abc import Iterable, Mapping
from typing import Any

_SENSITIVE_FIELDS = frozenset({"token", "api_key", "authorization", "password", "secret"})


def redact(value: Any, *, secrets: Iterable[str]) -> Any:
    """Return a copy of value with secrets and sensitive fields replaced.

    The input is not modified. Nested dictionaries and lists are copied too.
    """
    secret_values = tuple(secret for secret in secrets if secret)
    return _copy(value, secret_values)


def _copy(value: Any, secrets: tuple[str, ...]) -> Any:
    if isinstance(value, Mapping):
        copied: dict[Any, Any] = {}
        for key, item in value.items():
            if str(key).lower() in _SENSITIVE_FIELDS:
                copied[key] = "[redacted]"
            else:
                copied[key] = _copy(item, secrets)
        return copied
    if isinstance(value, list):
        return [_copy(item, secrets) for item in value]
    if isinstance(value, tuple):
        return tuple(_copy(item, secrets) for item in value)
    if isinstance(value, str):
        redacted = value
        for secret in secrets:
            redacted = redacted.replace(secret, "[redacted]")
        return redacted
    return value
