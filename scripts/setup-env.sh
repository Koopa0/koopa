#!/usr/bin/env bash
set -euo pipefail

# Generate .env files for blog stack deployment.
# Usage:
#   ./scripts/setup-env.sh              # Interactive mode
#   ./scripts/setup-env.sh --bitwarden  # Pull from Bitwarden vault

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BLOG_DIR="$(dirname "$SCRIPT_DIR")"
BLOG_ENV="$BLOG_DIR/.env"
OBS_ENV="$BLOG_DIR/../server/observability/.env"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# --- Bitwarden mode ---
if [[ "${1:-}" == "--bitwarden" ]]; then
    if ! command -v bw &>/dev/null; then
        error "Bitwarden CLI (bw) not found. Install: https://bitwarden.com/help/cli/"
        exit 1
    fi

    BW_STATUS=$(bw status | jq -r '.status')
    if [[ "$BW_STATUS" != "unlocked" ]]; then
        error "Bitwarden vault is locked. Run: bw unlock"
        exit 1
    fi

    info "Pulling secrets from Bitwarden vault..."

    BW_FOLDER="koopa0.dev"
    FOLDER_ID=$(bw list folders | jq -r ".[] | select(.name==\"$BW_FOLDER\") | .id")

    if [[ -z "$FOLDER_ID" ]]; then
        error "Bitwarden folder '$BW_FOLDER' not found."
        exit 1
    fi

    BLOG_ITEM=$(bw list items --folderid "$FOLDER_ID" | jq -r '.[] | select(.name=="blog-env")')
    if [[ -n "$BLOG_ITEM" ]]; then
        info "Writing $BLOG_ENV"
        echo "$BLOG_ITEM" | jq -r '.fields[] | "\(.name)=\(.value)"' > "$BLOG_ENV"
        chmod 600 "$BLOG_ENV"
        info "  $(wc -l < "$BLOG_ENV") variables written"
    else
        warn "Item 'blog-env' not found in Bitwarden"
    fi

    OBS_ITEM=$(bw list items --folderid "$FOLDER_ID" | jq -r '.[] | select(.name=="observability-env")')
    if [[ -n "$OBS_ITEM" ]]; then
        mkdir -p "$(dirname "$OBS_ENV")"
        info "Writing $OBS_ENV"
        echo "$OBS_ITEM" | jq -r '.fields[] | "\(.name)=\(.value)"' > "$OBS_ENV"
        chmod 600 "$OBS_ENV"
        info "  $(wc -l < "$OBS_ENV") variables written"
    else
        warn "Item 'observability-env' not found in Bitwarden"
    fi

    info "Done. Run 'docker compose up -d' to apply."
    exit 0
fi

# --- Interactive mode ---
info "Interactive .env setup for blog stack"
echo ""

if [[ -f "$BLOG_ENV" ]]; then
    warn "$BLOG_ENV already exists. Overwrite? [y/N]"
    read -r REPLY
    [[ "$REPLY" =~ ^[Yy]$ ]] || { info "Aborted."; exit 0; }
fi

prompt() {
    local var="$1" desc="$2" default="${3:-}"
    if [[ -n "$default" ]]; then
        echo -en "  ${var} (${desc}) [${default}]: "
        read -r val
        echo "${var}=${val:-$default}"
    else
        echo -en "  ${var} (${desc}): "
        read -r val
        echo "${var}=${val}"
    fi
}

generate() {
    local var="$1" desc="$2"
    local val
    val=$(openssl rand -base64 32 | tr -d '/+=' | head -c 32)
    info "  Generated ${var}"
    echo "${var}=${val}"
}

info "=== blog/.env ==="
{
    echo "# PostgreSQL"
    generate POSTGRES_PASSWORD "random 32 char"
    echo ""
    echo "# JWT"
    generate JWT_SECRET "random base64"
    echo ""
    echo "# Cloudflare R2"
    prompt R2_ACCESS_KEY_ID "R2 API token access key"
    prompt R2_SECRET_ACCESS_KEY "R2 API token secret"
    prompt R2_ENDPOINT "https://<ACCOUNT_ID>.r2.cloudflarestorage.com"
    prompt R2_BUCKET "R2 bucket name" "blog"
    prompt R2_PUBLIC_URL "https://pub-<hash>.r2.dev"
    echo ""
    echo "# GitHub"
    prompt GITHUB_WEBHOOK_SECRET "webhook secret"
    prompt GITHUB_TOKEN "fine-grained PAT"
    prompt GITHUB_REPO "owner/repo" "Koopa0/obsidian"
    echo ""
    echo "# AI"
    prompt GEMINI_API_KEY "Google AI Studio key"
    prompt ANTHROPIC_API_KEY "Anthropic Console key"
    echo ""
    echo "# Notion"
    prompt NOTION_API_KEY "internal integration secret"
    prompt NOTION_WEBHOOK_SECRET "webhook verification token"
    prompt NOTION_PROJECTS_DB "database ID"
    prompt NOTION_TASKS_DB "database ID"
    prompt NOTION_BOOKS_DB "database ID"
    echo ""
    echo "# Notifications"
    prompt LINE_CHANNEL_TOKEN "LINE channel access token"
    prompt LINE_USER_ID "LINE user ID"
    prompt TELEGRAM_BOT_TOKEN "Telegram bot token"
    prompt TELEGRAM_CHAT_ID "Telegram chat ID"
    echo ""
    echo "# Google OAuth"
    prompt GOOGLE_CLIENT_ID "OAuth client ID"
    prompt GOOGLE_CLIENT_SECRET "OAuth client secret"
    prompt GOOGLE_REDIRECT_URI "callback URL" "https://koopa0.dev/api/auth/google/callback"
    prompt ADMIN_EMAIL "admin Google email"
} > "$BLOG_ENV"

chmod 600 "$BLOG_ENV"
info "$BLOG_ENV written ($(wc -l < "$BLOG_ENV") lines)"

echo ""
info "=== server/observability/.env ==="
warn "Generate observability .env too? [y/N]"
read -r REPLY
if [[ "$REPLY" =~ ^[Yy]$ ]]; then
    mkdir -p "$(dirname "$OBS_ENV")"
    {
        echo "GRAFANA_ADMIN_USER=admin"
        generate GRAFANA_ADMIN_PASSWORD "random 32 char"
        prompt TELEGRAM_BOT_TOKEN "same as blog"
        prompt TELEGRAM_CHAT_ID_CRITICAL "critical alerts group"
        prompt TELEGRAM_CHAT_ID_WARNING "warning alerts group"
    } > "$OBS_ENV"
    chmod 600 "$OBS_ENV"
    info "$OBS_ENV written"
fi

echo ""
info "Done. Next steps:"
echo "  1. Review .env files"
echo "  2. docker compose up -d"
echo "  3. Save values to Bitwarden vault"
