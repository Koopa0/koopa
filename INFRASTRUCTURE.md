# Infrastructure 文件

## 架構

```
瀏覽器 ─HTTPS─▶ Cloudflare (Edge/TLS) ─Tunnel─▶ VPS:4000 (SSR) ─HTTP─▶ backend:8080 ─▶ postgres:5432
                                                       │                                       │
                                                       └── BFF proxy /bff/*                    └── R2 (S3)
```

## VPS

- **Provider**: Hostinger KVM 2
- **IP**: 46.202.155.7
- **OS**: Ubuntu 24.04
- **Specs**: 2 vCPU / 8GB RAM / 96GB disk
- **User**: `koopa` (no root SSH)

## 安全配置

| 項目 | 狀態 |
|------|------|
| SSH key-only | `PasswordAuthentication no` |
| fail2ban | 啟用，保護 SSH |
| UFW | 啟用，僅允許 port 22 |
| Docker port | `127.0.0.1:4000` (不對外) |
| unattended-upgrades | 啟用 |
| Backend/Postgres | Docker internal network，不暴露 |
| Security headers | HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| X-Powered-By | 已移除 |

## Cloudflare

| 設定 | 值 |
|------|-----|
| SSL/TLS 模式 | Full |
| Always Use HTTPS | 開啟 |
| Tunnel | `koopa-tunnel` → `http://localhost:4000` |
| DMARC | `v=DMARC1; p=reject; adkim=s; aspf=s;` |
| Email Routing | `contact@koopa0.dev` → 個人信箱 |
| Zero Trust Access | 保護 `/admin`, `/login` (Owner Only) |

## Docker Services

| Service | Image | Port | 暴露 |
|---------|-------|------|------|
| frontend | node:22-alpine (Angular 21 SSR) | 4000 | 127.0.0.1 only |
| backend | Go 1.26 | 8080 | internal network |
| postgres | postgres:17-alpine | 5432 | internal network |

## 環境變數

Production `.env` 在 VPS `~/blog/.env`，由 docker-compose 讀取。
完整範例見 `/.env.example`。

| 變數 | 用途 | 來源 |
|------|------|------|
| `POSTGRES_PASSWORD` | PostgreSQL 密碼 | 隨機生成 |
| `JWT_SECRET` | JWT 簽發密鑰 | 隨機生成 |
| `R2_ACCESS_KEY_ID` | Cloudflare R2 存取金鑰 | Cloudflare Dashboard → R2 → API Tokens |
| `R2_SECRET_ACCESS_KEY` | R2 秘密金鑰 | 同上（建立時只顯示一次） |
| `R2_ENDPOINT` | R2 S3 端點 | `https://<ACCOUNT_ID>.r2.cloudflarestorage.com` |
| `R2_BUCKET` | R2 bucket 名稱 | `blog` |
| `R2_PUBLIC_URL` | R2 公開存取 URL | Cloudflare Dashboard → R2 → bucket → Settings → Public access |
| `GITHUB_WEBHOOK_SECRET` | GitHub Webhook HMAC 驗證 | GitHub repo → Settings → Webhooks → Secret |
| `GITHUB_TOKEN` | GitHub PAT (Obsidian repo 讀取) | GitHub → Settings → Developer settings → Personal access tokens |
| `GITHUB_REPO` | Obsidian 內容來源 repo | `Koopa0/obsidian` |

### Secrets 備份策略

1. **VPS `.env`** 是唯一的 production secrets 來源
2. **不要把 `.env` commit 到 git**（已在 `.gitignore`）
3. **備份方式**：`scp -i ~/.ssh/id_vps koopa@46.202.155.7:~/blog/.env ./blog-env-backup-$(date +%Y%m%d)`
4. **重建 secrets**：
   - `POSTGRES_PASSWORD` / `JWT_SECRET`：重新生成（`openssl rand -base64 32`），但會導致現有 session / 密碼失效
   - `R2_*`：去 Cloudflare Dashboard 重新建立 API Token（IP 鎖定 VPS）
   - `GITHUB_TOKEN`：去 GitHub 重新建立 PAT
   - `GITHUB_WEBHOOK_SECRET`：去 GitHub Webhook 設定頁更新

## CI/CD

### GitHub Actions

`.github/workflows/deploy.yml`：
- 觸發：push to `main`
- 流程：SSH → git pull → docker compose up --build → prune images

GitHub Secrets（repo → Settings → Secrets and variables → Actions）：

| Secret | 值 | 來源 |
|--------|-----|------|
| `VPS_HOST` | `46.202.155.7` | Hostinger hPanel |
| `VPS_USER` | `koopa` | VPS 使用者 |
| `VPS_SSH_KEY` | `~/.ssh/id_vps` 私鑰內容 | 本地 SSH key |

### GitHub Webhook

- **Repo**: `Koopa0/obsidian`
- **Payload URL**: `https://koopa0.dev/bff/api/webhook/github`
- **Content type**: `application/json`
- **Secret**: 與 VPS `.env` 的 `GITHUB_WEBHOOK_SECRET` 一致
- **Events**: Push events

## SSH 存取

```bash
ssh -i ~/.ssh/id_vps koopa@46.202.155.7
```

換電腦時：備份 `~/.ssh/id_vps`，或用 Hostinger VNC console 加新 public key 到 `~/.ssh/authorized_keys`。

## 手動部署

```bash
ssh -i ~/.ssh/id_vps koopa@46.202.155.7
cd ~/blog && git pull && docker compose up -d --build && docker image prune -f
```

## 多專案擴展

同一條 Cloudflare Tunnel 支援多個 hostname：

```
koopa0.dev           → http://localhost:4000  (blog)
resonance.koopa0.dev → http://localhost:4001  (future)
```

每個專案獨立 Docker Compose，共用 VPS 和 Tunnel。
