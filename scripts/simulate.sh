#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="${DIR}/../src"
exec "${DIR}/../.venv/bin/python" -m wardline.simulation --scenario all --mode inprocess "$@"
