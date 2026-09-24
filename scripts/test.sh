#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
ulimit -n 4096 2>/dev/null || true

if [ ! -x .venv/bin/python ]; then
  echo "missing .venv; run ./scripts/setup.sh" >&2
  exit 1
fi

.venv/bin/ruff check src tests
.venv/bin/mypy src
.venv/bin/pytest -q
