"""Security test: ensure laboratory keys never appear in source code under src/."""

from pathlib import Path

_SRC_ROOT = Path(__file__).resolve().parents[2] / "src"
_FORBIDDEN_KEYS = ("dev-viewer-key", "dev-operator-key", "dev-admin-key")


def test_source_tree_has_no_dev_keys() -> None:
    found_violations: list[str] = []
    for path in _SRC_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for key in _FORBIDDEN_KEYS:
            if key in text:
                found_violations.append(f"{path}: contains forbidden key {key}")
    assert not found_violations, f"Forbidden keys found in source code: {found_violations}"
