#!/usr/bin/env bash
set -e
# Run from workspace root (task cwd is already workspaceFolder)
if [[ -f .env ]]; then
  set -a
  source .env
  set +a
fi
exec "$@"
