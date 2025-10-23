package security

import (
	"fmt"
	"strings"
)

// EnvValidator 環境變數驗證器
// 用於防止敏感信息泄露
type EnvValidator struct {
	sensitivePatterns []string
}

// NewEnvValidator 創建環境變數驗證器
func NewEnvValidator() *EnvValidator {
	return &EnvValidator{
		sensitivePatterns: []string{
			// API 金鑰和認證憑證
			"API_KEY",
			"APIKEY",
			"SECRET",
			"PASSWORD",
			"PASSWD",
			"PWD",
			"TOKEN",
			"ACCESS_TOKEN",
			"REFRESH_TOKEN",
			"AUTH",
			"CREDENTIALS",
			"PRIVATE_KEY",
			"PRIV_KEY",

			// 雲服務相關
			"AWS_SECRET",
			"AWS_ACCESS_KEY",
			"AZURE_",
			"GCP_",
			"GOOGLE_API",
			"GOOGLE_APPLICATION_CREDENTIALS",

			// 資料庫相關
			"DB_PASSWORD",
			"DB_PASS",
			"DATABASE_PASSWORD",
			"DATABASE_URL", // 可能包含密碼
			"REDIS_PASSWORD",
			"MONGO_PASSWORD",
			"POSTGRES_PASSWORD",
			"MYSQL_PASSWORD",

			// OAuth 和第三方服務
			"OAUTH",
			"GITHUB_TOKEN",
			"GITLAB_TOKEN",
			"SLACK_TOKEN",
			"DISCORD_TOKEN",
			"TELEGRAM_TOKEN",

			// 加密相關
			"ENCRYPTION_KEY",
			"ENCRYPT_KEY",
			"CIPHER_KEY",
			"SALT",
			"HASH_KEY",
			"SIGNING_KEY",

			// 郵件服務
			"SMTP_PASSWORD",
			"MAIL_PASSWORD",
			"EMAIL_PASSWORD",

			// 支付相關
			"STRIPE_SECRET",
			"PAYPAL_SECRET",
			"PAYMENT_KEY",

			// Session 和 Cookie
			"SESSION_SECRET",
			"COOKIE_SECRET",

			// AI 服務 (Gemini, OpenAI 等)
			"GEMINI_API_KEY",
			"OPENAI_API_KEY",
			"ANTHROPIC_API_KEY",
			"HUGGINGFACE_TOKEN",
		},
	}
}

// ValidateEnvAccess 驗證是否允許訪問指定的環境變數
func (v *EnvValidator) ValidateEnvAccess(envName string) error {
	envUpper := strings.ToUpper(envName)

	// 檢查是否匹配敏感模式
	for _, pattern := range v.sensitivePatterns {
		if strings.Contains(envUpper, pattern) {
			return fmt.Errorf("拒絕訪問敏感環境變數: %s（匹配模式: %s）", envName, pattern)
		}
	}

	return nil
}

// IsSensitiveEnv 快速檢查環境變數名稱是否明顯敏感
// 這是一個額外的保護層
func IsSensitiveEnv(envName string) bool {
	envUpper := strings.ToUpper(envName)

	quickPatterns := []string{
		"SECRET",
		"PASSWORD",
		"TOKEN",
		"KEY",
		"CREDENTIALS",
	}

	for _, pattern := range quickPatterns {
		if strings.Contains(envUpper, pattern) {
			return true
		}
	}

	return false
}

// GetAllowedEnvNames 獲取明確允許訪問的環境變數列表（白名單）
// 這些是常見的非敏感環境變數
func GetAllowedEnvNames() []string {
	return []string{
		// 系統信息
		"PATH",
		"HOME",
		"USER",
		"SHELL",
		"TERM",
		"LANG",
		"LC_ALL",
		"TZ",

		// Go 相關
		"GOPATH",
		"GOROOT",
		"GOOS",
		"GOARCH",
		"GO111MODULE",

		// 一般開發
		"EDITOR",
		"VISUAL",
		"PAGER",

		// 代理設定（不包含認證）
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"NO_PROXY",

		// 日誌等級
		"LOG_LEVEL",
		"DEBUG",

		// 應用程序名稱和版本（非敏感）
		"APP_NAME",
		"APP_VERSION",
		"NODE_ENV",
		"ENVIRONMENT",
	}
}
