#!/usr/bin/env bash
set -euo pipefail
: "${ATLAS_PRIVATE_HOST:?Set exact Tailscale hostname without https://}"
export ATLAS_PRIVATE_MODE=1
export ATLAS_DATA_DIR="${ATLAS_DATA_DIR:-$HOME/ATLAS/data}"
export ATLAS_BACKUP_DIR="${ATLAS_BACKUP_DIR:-$HOME/ATLAS/backups}"
exec python3 "$(dirname "$0")/atlas.py"
