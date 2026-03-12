#!/usr/bin/env bash
set -euo pipefail

# Generate a Bitwarden-compatible JSON import file from VPS .env files.
# Usage: ./scripts/export-to-bitwarden.sh > bw-import.json
# Then import via Bitwarden Web Vault or CLI.

VPS="koopa@46.202.155.7"
SSH_KEY="$HOME/.ssh/id_vps"

echo "Pulling secrets from VPS..." >&2

BLOG_ENV=$(ssh -i "$SSH_KEY" "$VPS" "grep -v '^#' ~/blog/.env | grep -v '^\$' | grep '='")
OBS_ENV=$(ssh -i "$SSH_KEY" "$VPS" "grep -v '^#' ~/server/observability/.env | grep -v '^\$' | grep '='")

blog_fields=$(echo "$BLOG_ENV" | while IFS='=' read -r key val; do
  jq -n --arg name "$key" --arg value "$val" '{"name":$name,"value":$value,"type":0}'
done | jq -s '.')

obs_fields=$(echo "$OBS_ENV" | while IFS='=' read -r key val; do
  jq -n --arg name "$key" --arg value "$val" '{"name":$name,"value":$value,"type":0}'
done | jq -s '.')

jq -n \
  --argjson blog_fields "$blog_fields" \
  --argjson obs_fields "$obs_fields" \
  '{
    "encrypted": false,
    "folders": [],
    "items": [
      {
        "type": 2,
        "name": "blog-env",
        "notes": "Production blog stack secrets (~/blog/.env on VPS)",
        "favorite": false,
        "folderName": "koopa0.dev",
        "secureNote": {},
        "fields": $blog_fields
      },
      {
        "type": 2,
        "name": "observability-env",
        "notes": "Observability stack secrets (~/server/observability/.env on VPS)",
        "favorite": false,
        "folderName": "koopa0.dev",
        "secureNote": {},
        "fields": $obs_fields
      }
    ]
  }'

echo "Done. Import via Bitwarden (Settings → Import Data → Bitwarden JSON)." >&2
