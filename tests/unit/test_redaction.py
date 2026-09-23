"""Unit tests for secret and sensitive field redaction."""

from wardline.security.redaction import redact


def test_redact_replaces_key_material() -> None:
    secret = "dev-admin-key"
    text = f"authenticated with secret {secret} successfully"
    result = redact(text, secrets=[secret])
    assert secret not in result
    assert result == "authenticated with secret [redacted] successfully"

    payload = {"message": f"token {secret} leaked", "status": "failed"}
    redacted_payload = redact(payload, secrets=[secret])
    assert secret not in str(redacted_payload)
    assert redacted_payload["message"] == "token [redacted] leaked"
    assert redacted_payload["status"] == "failed"


def test_redact_replaces_sensitive_field_names() -> None:
    data = {
        "token": "secret-value-123",
        "api_key": "some-key",
        "authorization": "Bearer whatever",
        "password": "my-password",
        "secret": "top-secret",
        "nested": {
            "token": "nested-token",
            "safe": "safe-value",
        },
    }
    redacted_data = redact(data, secrets=[])
    assert redacted_data["token"] == "[redacted]"
    assert redacted_data["api_key"] == "[redacted]"
    assert redacted_data["authorization"] == "[redacted]"
    assert redacted_data["password"] == "[redacted]"
    assert redacted_data["secret"] == "[redacted]"
    assert redacted_data["nested"]["token"] == "[redacted]"
    assert redacted_data["nested"]["safe"] == "safe-value"


def test_redact_does_not_share_nested_mutations() -> None:
    original = {
        "config": {
            "token": "my-token",
            "tags": ["alpha", "beta"],
        },
        "meta": {"name": "test"},
    }
    result = redact(original, secrets=["beta"])
    assert original["config"]["token"] == "my-token"
    assert original["config"]["tags"] == ["alpha", "beta"]

    # Mutate the result and verify original remains unchanged
    result["config"]["token"] = "changed"
    result["config"]["tags"].append("gamma")
    assert original["config"]["token"] == "my-token"
    assert original["config"]["tags"] == ["alpha", "beta"]
