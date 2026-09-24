"""Command-line entrypoint for resetting local laboratory data."""

from pathlib import Path

from wardline.storage.cleanup import safe_reset


def main() -> None:
    data_dir = Path("./data")
    removed = safe_reset(data_dir)
    if not removed:
        print("nothing to reset")
    else:
        for p in removed:
            print(f"removed: {p}")


if __name__ == "__main__":
    main()
