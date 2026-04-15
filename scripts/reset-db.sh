#!/usr/bin/env bash
# reset-db.sh — wipe and rebuild the koopa0.dev PostgreSQL schema.
#
# WHY THIS EXISTS
#   The coordination rebuild (docs/architecture/coordination-layer-target.md)
#   is a non-backwards-compatible schema change executed by editing
#   migrations/001_initial.up.sql in place rather than adding new migration
#   files. Golang-migrate records migration versions, not file contents —
#   so `migrate up` on an already-migrated database is a no-op even when
#   001 has been rewritten. To pick up the new schema you must drop and
#   recreate the public schema, then re-run migrations from zero.
#
# USAGE
#   DATABASE_URL="postgres://user:pass@host/db" ./scripts/reset-db.sh
#
#   Or with per-component vars:
#     PGHOST=... PGUSER=... PGDATABASE=... ./scripts/reset-db.sh
#
# SAFETY
#   This script is DESTRUCTIVE. It drops the entire public schema and all
#   data in it. It refuses to run without an explicit --yes flag or
#   KOOPA_RESET_CONFIRM=1 environment variable. Backups are your problem —
#   take one before running against any database whose data you care about.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MIGRATIONS_DIR="${REPO_ROOT}/migrations"

confirm() {
    if [[ "${KOOPA_RESET_CONFIRM:-}" == "1" ]]; then
        return 0
    fi
    if [[ "${1:-}" == "--yes" || "${1:-}" == "-y" ]]; then
        return 0
    fi
    cat >&2 <<EOF
reset-db.sh will DROP SCHEMA public CASCADE on the target database and re-run
migrations from zero. All data will be destroyed.

Target: ${DATABASE_URL:-<PG* environment variables>}

Pass --yes (or set KOOPA_RESET_CONFIRM=1) to proceed.
EOF
    exit 1
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: required tool '$1' not found on PATH" >&2
        exit 1
    fi
}

confirm "$@"
require_tool psql
require_tool migrate

if [[ -z "${DATABASE_URL:-}" ]]; then
    echo "error: DATABASE_URL must be set" >&2
    exit 1
fi

echo "==> dropping and recreating public schema"
psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 <<'SQL'
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;
GRANT ALL ON SCHEMA public TO CURRENT_USER;
GRANT ALL ON SCHEMA public TO public;
SQL

echo "==> running migrations from zero"
migrate -database "${DATABASE_URL}" -path "${MIGRATIONS_DIR}" up

echo "==> done. current migration version:"
migrate -database "${DATABASE_URL}" -path "${MIGRATIONS_DIR}" version
