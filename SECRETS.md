# Secrets Reference

All secrets needed to run the blog stack. **Never commit actual values.**

## blog/.env

| Variable | Source | How to regenerate |
|---|---|---|
| `POSTGRES_PASSWORD` | Self-generated | `openssl rand -base64 32` |
| `JWT_SECRET` | Self-generated | `openssl rand -base64 64` |
| `R2_ACCESS_KEY_ID` | Cloudflare Dashboard → R2 → Manage R2 API Tokens | Create token with Object Read & Write |
| `R2_SECRET_ACCESS_KEY` | Same as above | Shown once at creation |
| `R2_ENDPOINT` | Cloudflare Dashboard → R2 → bucket detail | `https://<ACCOUNT_ID>.r2.cloudflarestorage.com` |
| `R2_BUCKET` | Cloudflare R2 | Bucket name (default: `blog`) |
| `R2_PUBLIC_URL` | Cloudflare R2 → bucket → Settings → Public access | `https://pub-<hash>.r2.dev` |
| `GITHUB_WEBHOOK_SECRET` | GitHub repo → Settings → Webhooks → Secret | Any random string, must match GitHub config |
| `GITHUB_TOKEN` | GitHub → Settings → Developer settings → Fine-grained PAT | Scope: repo contents read on `Koopa0/obsidian` |
| `GITHUB_REPO` | Config value | `Koopa0/obsidian` (not a secret) |
| `GEMINI_API_KEY` | Google AI Studio → API keys | Create new key |
| `ANTHROPIC_API_KEY` | Anthropic Console → API keys | Create new key |
| `NOTION_API_KEY` | Notion → Settings → Integrations → "koopa0.dev" | Internal integration secret |
| `NOTION_WEBHOOK_SECRET` | Notion webhook verification flow | The verification_token from Notion's POST |
| `NOTION_PROJECTS_DB` | Notion database URL | Extract ID from URL (not a secret) |
| `NOTION_TASKS_DB` | Same as above | Extract ID from URL |
| `NOTION_BOOKS_DB` | Same as above | Extract ID from URL |
| `LINE_CHANNEL_TOKEN` | LINE Developers Console → Channel → Messaging API | Long-lived channel access token |
| `LINE_USER_ID` | LINE Developers Console → Channel → Basic settings | Your LINE user ID |
| `TELEGRAM_BOT_TOKEN` | Telegram @BotFather → /newbot or /token | Revoke with /revoke |
| `TELEGRAM_CHAT_ID` | Telegram Bot API `getUpdates` | Group chat ID (negative number) |
| `GOOGLE_CLIENT_ID` | Google Cloud Console → Credentials → OAuth 2.0 | Blog OAuth client (not Cloudflare Access one) |
| `GOOGLE_CLIENT_SECRET` | Same as above | Shown in credential detail |
| `GOOGLE_REDIRECT_URI` | Config value | `https://koopa0.dev/api/auth/google/callback` |
| `ADMIN_EMAIL` | Config value | Your Google account email |

## server/observability/.env

| Variable | Source | How to regenerate |
|---|---|---|
| `GRAFANA_ADMIN_USER` | Config value | Default: `admin` |
| `GRAFANA_ADMIN_PASSWORD` | Self-generated | `openssl rand -base64 32` |
| `TELEGRAM_BOT_TOKEN` | Same as blog's | Shared token |
| `TELEGRAM_CHAT_ID_CRITICAL` | Telegram Bot API | Critical alerts group chat ID |
| `TELEGRAM_CHAT_ID_WARNING` | Telegram Bot API | Warning alerts group chat ID |

## GitHub Actions Secrets

| Secret | Source |
|---|---|
| `VPS_HOST` | VPS IP address |
| `VPS_USER` | SSH username |
| `VPS_SSH_KEY` | SSH private key (should be separate deploy key, not personal) |

## Rotation checklist

1. Generate new value
2. Update VPS `~/blog/.env` (or `~/server/observability/.env`)
3. `docker compose up -d` to reload (NOT `restart`)
4. Update Bitwarden vault
5. If webhook secret: update the matching service (GitHub/Notion) config too
