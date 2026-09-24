"""Storage cleanup and safe reset utilities."""

from pathlib import Path

_RESETTABLE_EXTENSIONS = {".db", ".db-shm", ".db-wal", ".jsonl"}


def safe_reset(data_dir: Path) -> list[Path]:
    """Safely reset data directory by removing only local databases and .jsonl files.

    Strictly rejects any path whose final directory name is not 'data'.
    Never touches code, .env, or virtual environments.
    Returns the list of removed paths.
    """
    resolved = data_dir.resolve()
    if data_dir.name != "data" and resolved.name != "data":
        raise ValueError(f"Refusing to reset directory not named 'data': {data_dir}")

    if not data_dir.exists():
        return []

    removed: list[Path] = []
    # Search all files in data_dir recursively
    for path in data_dir.rglob("*"):
        if path.is_file() and path.suffix in _RESETTABLE_EXTENSIONS:
            path.unlink()
            removed.append(path)

    return removed
