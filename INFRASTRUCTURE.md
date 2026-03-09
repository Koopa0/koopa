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

| 變數 | 用途 |
|------|------|
| `POSTGRES_PASSWORD` | PostgreSQL 密碼 |
| `JWT_SECRET` | JWT 簽發密鑰 |
| `R2_ACCESS_KEY_ID` | Cloudflare R2 存取金鑰 |
| `R2_SECRET_ACCESS_KEY` | R2 秘密金鑰 |
| `R2_ENDPOINT` | R2 S3 端點 |
| `R2_BUCKET` | R2 bucket 名稱 |

## CI/CD

GitHub Actions (`.github/workflows/deploy.yml`)：
- 觸發：push to `main`
- 流程：SSH → git pull → docker compose up --build
- 需要的 GitHub Secrets：`VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY`

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
