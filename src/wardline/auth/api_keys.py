"""Parse the laboratory API-key string. Keys are not logged."""

from wardline.contracts import ErrorCode, Role
from wardline.errors import WardlineError


def parse_dev_api_keys(raw: str) -> dict[Role, str]:
    """Return role to key. An empty string means no keys are configured.

    Rejects unknown roles, empty keys, duplicate roles, and any whitespace
    inside a key. The values are returned as given so a later prompt can hash
    them. This function does not write a log line.
    """
    if raw.strip() == "":
        return {}
    found: dict[Role, str] = {}
    for segment in raw.split(","):
        entry = segment.strip()
        if entry == "":
            raise WardlineError(ErrorCode.validation_error, "empty api key entry")
        role_text, separator, key = entry.partition(":")
        if separator != ":" or role_text == "":
            raise WardlineError(ErrorCode.validation_error, "api key entry must be role:key")
        try:
            role = Role(role_text)
        except ValueError as caught:
            raise WardlineError(ErrorCode.validation_error, "unknown api key role") from caught
        if key == "" or any(character.isspace() for character in key):
            raise WardlineError(ErrorCode.validation_error, "api key value is empty or spaced")
        if role in found:
            raise WardlineError(ErrorCode.validation_error, "duplicate api key role")
        found[role] = key
    return found
