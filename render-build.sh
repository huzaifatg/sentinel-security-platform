#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
printf '%s\n' '==> Installing Python dependencies'
python -m pip install -r requirements.txt
printf '%s\n' '==> Running Alembic migrations'
python -m alembic upgrade head
printf '%s\n' '==> Alembic migrations completed successfully'
