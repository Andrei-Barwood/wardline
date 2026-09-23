#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"

if [ ! -x .venv/bin/python ]; then
  echo "missing .venv; run ./scripts/setup.sh" >&2
  exit 1
fi

if [ -f .env ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      "" | \#*)
        continue
        ;;
      WARDLINE_*=*)
        key=${line%%=*}
        value=${line#*=}
        export "$key=$value"
        ;;
    esac
  done < .env
fi

exec .venv/bin/python -m wardline
