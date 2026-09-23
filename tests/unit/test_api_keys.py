"""Unit tests for API-key hashing, registry lookup, and constant-time comparison."""

from wardline.auth.api_keys import ApiKeyRegistry, hash_key
from wardline.contracts import Role

_RAW_KEYS = "viewer:dev-viewer-key,operator:dev-operator-key,admin:dev-admin-key"


def test_hash_key_is_sha256_length() -> None:
    digest = hash_key("some-test-key")
    assert isinstance(digest, bytes)
    assert len(digest) == 32


def test_unknown_token_returns_none() -> None:
    registry = ApiKeyRegistry(_RAW_KEYS)
    assert registry.role_for_token("totally-unknown-key") is None
    assert registry.role_for_token("") is None
    assert registry.role_for_token(None) is None


def test_each_role_maps_to_its_key() -> None:
    registry = ApiKeyRegistry(_RAW_KEYS)
    assert registry.role_for_token("dev-viewer-key") == Role.VIEWER
    assert registry.role_for_token("dev-operator-key") == Role.OPERATOR
    assert registry.role_for_token("dev-admin-key") == Role.ADMIN


def test_compare_does_not_return_principal_on_partial_key() -> None:
    registry = ApiKeyRegistry(_RAW_KEYS)
    assert registry.role_for_token("dev-admin-key-extra") is None
    assert registry.role_for_token("dev-admin-ke") is None
    assert registry.role_for_token("dev-admin-key-nope") is None
    assert registry.role_for_token("x-dev-admin-key") is None
