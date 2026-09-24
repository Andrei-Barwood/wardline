"""Storage cleanup and safe reset utilities."""

from pathlib import Path

_RESETTABLE_EXTENSIONS = {".db", ".db-shm", ".db-wal", ".jsonl"}


def safe_reset(data_dir: Path, *, allowed_root: Path) -> list[Path]:
    """Safely reset data directory by removing only local databases and .jsonl files.

    Strictly rejects any path whose final directory name after resolution is not 'data',
    or which is not contained within the specified allowed root directory.
    Never touches code, .env, or virtual environments.
    Returns the list of removed paths.
    """
    resolved_root = allowed_root.resolve()
    resolved_data = data_dir.resolve()

    if resolved_data.name != "data":
        raise ValueError(f"Refusing to reset directory not named 'data': {data_dir}")

    try:
        resolved_data.relative_to(resolved_root)
    except ValueError:
        raise ValueError(
            f"Path escape detected: {data_dir} resolves outside allowed root {allowed_root}"
        ) from None

    if resolved_data == resolved_root:
        raise ValueError(f"Refusing to reset root directory: {data_dir}")

    if not resolved_data.exists():
        return []

    removed: list[Path] = []
    # Search all files in resolved_data recursively
    for path in resolved_data.rglob("*"):
        if path.is_file() and path.suffix in _RESETTABLE_EXTENSIONS:
            path.unlink()
            removed.append(path)

    return removed
