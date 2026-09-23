#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"

pick_python() {
  for candidate in python3.13 python3.12 python3.14 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
      if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)'; then
        echo "$candidate"
        return 0
      fi
    fi
  done
  echo "Python 3.12 or newer is required" >&2
  return 1
}

if [ ! -d .venv ]; then
  "$(pick_python)" -m venv .venv
fi

.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev]"

if [ ! -f .env ]; then
  cp .env.example .env
fi

mkdir -p data/logs
