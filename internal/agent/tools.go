package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/koopa0/koopa/internal/security"
)

// cmdValidator 命令驗證器（使用統一的安全模塊）
var cmdValidator = security.NewCommandValidator()

// httpValidator HTTP 請求驗證器（防止 SSRF 攻擊）
var httpValidator = security.NewHTTPValidator()

// envValidator 環境變數驗證器（防止敏感信息泄露）
var envValidator = security.NewEnvValidator()

// registerTools 註冊所有可用的工具
func registerTools(g *genkit.Genkit) {
	// 1. 獲取當前時間
	genkit.DefineTool(
		g, "currentTime", "獲取當前時間",
		func(ctx *ai.ToolContext, input struct{}) (string, error) {
			now := time.Now()
			return now.Format("2006-01-02 15:04:05 (Monday)"), nil
		},
	)

	// 2. 讀取檔案
	genkit.DefineTool(
		g, "readFile", "讀取檔案內容",
		func(ctx *ai.ToolContext, input struct {
			Path string `json:"path" jsonschema_description:"要讀取的檔案路徑"`
		},
		) (string, error) {
			// 路徑安全驗證（防止路徑遍歷攻擊 CWE-22）
			safePath, err := pathValidator.ValidatePath(input.Path)
			if err != nil {
				return "", fmt.Errorf("路徑驗證失敗: %w", err)
			}

			content, err := os.ReadFile(safePath)
			if err != nil {
				return "", fmt.Errorf("無法讀取檔案: %w", err)
			}
			return string(content), nil
		},
	)

	// 3. 寫入檔案
	genkit.DefineTool(
		g, "writeFile", "寫入內容到檔案",
		func(ctx *ai.ToolContext, input struct {
			Path    string `json:"path" jsonschema_description:"要寫入的檔案路徑"`
			Content string `json:"content" jsonschema_description:"要寫入的內容"`
		},
		) (string, error) {
			// 路徑安全驗證（防止路徑遍歷攻擊 CWE-22）
			safePath, err := pathValidator.ValidatePath(input.Path)
			if err != nil {
				return "", fmt.Errorf("路徑驗證失敗: %w", err)
			}

			// 確保目錄存在（使用 0750 權限提高安全性）
			dir := filepath.Dir(safePath)
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return "", fmt.Errorf("無法創建目錄: %w", err)
			}

			if err = os.WriteFile(safePath, []byte(input.Content), 0o600); err != nil {
				return "", fmt.Errorf("無法寫入檔案: %w", err)
			}
			return fmt.Sprintf("成功寫入檔案: %s", safePath), nil
		},
	)

	// 4. 列出目錄內容
	genkit.DefineTool(
		g, "listFiles", "列出目錄中的檔案和子目錄",
		func(ctx *ai.ToolContext, input struct {
			Path string `json:"path" jsonschema_description:"要列出的目錄路徑"`
		},
		) (string, error) {
			// 路徑安全驗證
			safePath, err := pathValidator.ValidatePath(input.Path)
			if err != nil {
				return "", fmt.Errorf("路徑驗證失敗: %w", err)
			}

			entries, err := os.ReadDir(safePath)
			if err != nil {
				return "", fmt.Errorf("無法讀取目錄: %w", err)
			}

			var result []string
			for _, entry := range entries {
				prefix := "[檔案]"
				if entry.IsDir() {
					prefix = "[目錄]"
				}
				result = append(result, fmt.Sprintf("%s %s", prefix, entry.Name()))
			}

			return strings.Join(result, "\n"), nil
		},
	)

	// 5. 刪除檔案
	genkit.DefineTool(
		g, "deleteFile", "刪除指定的檔案",
		func(ctx *ai.ToolContext, input struct {
			Path string `json:"path" jsonschema_description:"要刪除的檔案路徑"`
		},
		) (string, error) {
			// 路徑安全驗證
			safePath, err := pathValidator.ValidatePath(input.Path)
			if err != nil {
				return "", fmt.Errorf("路徑驗證失敗: %w", err)
			}

			if err = os.Remove(safePath); err != nil {
				return "", fmt.Errorf("無法刪除檔案: %w", err)
			}
			return fmt.Sprintf("成功刪除檔案: %s", safePath), nil
		},
	)

	// 6. 執行系統命令
	genkit.DefineTool(
		g, "executeCommand", "執行系統命令（謹慎使用，會自動檢查危險命令）",
		func(ctx *ai.ToolContext, input struct {
			Command string   `json:"command" jsonschema_description:"要執行的命令"`
			Args    []string `json:"args,omitempty" jsonschema_description:"命令參數（可選）"`
		},
		) (string, error) {
			// 命令安全驗證（防止命令注入攻擊 CWE-78）
			if err := cmdValidator.ValidateCommand(input.Command, input.Args); err != nil {
				return "", fmt.Errorf("⚠️  安全警告：拒絕執行危險命令\n命令: %s %s\n原因: %w\n如需執行，請使用者手動在終端執行",
					input.Command, strings.Join(input.Args, " "), err)
			}

			cmd := exec.Command(input.Command, input.Args...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				return "", fmt.Errorf("命令執行失敗: %w\n輸出: %s", err, string(output))
			}
			return string(output), nil
		},
	)

	// 7. HTTP GET 請求（帶有 SSRF 防護）
	genkit.DefineTool(
		g, "httpGet", "發送 HTTP GET 請求（已啟用 SSRF 防護）",
		func(ctx *ai.ToolContext, input struct {
			URL string `json:"url" jsonschema_description:"要請求的 URL"`
		},
		) (string, error) {
			// URL 安全驗證（防止 SSRF 攻擊）
			if err := httpValidator.ValidateURL(input.URL); err != nil {
				return "", fmt.Errorf("⚠️  安全警告：URL 驗證失敗\n原因: %w\n這可能是嘗試訪問內部網絡或元數據服務", err)
			}

			// 使用安全配置的 HTTP 客戶端（帶超時和重定向限制）
			client := httpValidator.CreateSafeHTTPClient()
			resp, err := client.Get(input.URL)
			if err != nil {
				return "", fmt.Errorf("HTTP 請求失敗: %w", err)
			}
			defer resp.Body.Close()

			// 限制回應大小（防止資源耗盡）
			maxSize := httpValidator.GetMaxResponseSize()
			limitedReader := io.LimitReader(resp.Body, maxSize)

			body, err := io.ReadAll(limitedReader)
			if err != nil {
				return "", fmt.Errorf("讀取回應失敗: %w", err)
			}

			// 檢查是否超過大小限制
			if int64(len(body)) >= maxSize {
				return "", fmt.Errorf("回應大小超過限制（最大 %d MB）", maxSize/(1024*1024))
			}

			result := map[string]any{
				"status": resp.StatusCode,
				"body":   string(body),
			}

			jsonResult, _ := json.Marshal(result)
			return string(jsonResult), nil
		},
	)

	// 8. 讀取環境變數（受限制的訪問）
	genkit.DefineTool(
		g, "getEnv", "讀取環境變數（敏感變數受保護）",
		func(ctx *ai.ToolContext, input struct {
			Name string `json:"name" jsonschema_description:"環境變數名稱"`
		},
		) (string, error) {
			// 環境變數安全驗證（防止敏感信息泄露）
			if err := envValidator.ValidateEnvAccess(input.Name); err != nil {
				return "", fmt.Errorf("⚠️  安全警告：%w\n提示：此環境變數可能包含敏感信息，已被保護。\n如需訪問，請使用者直接在終端查看", err)
			}

			value := os.Getenv(input.Name)
			if value == "" {
				return fmt.Sprintf("環境變數 %s 未設定或為空", input.Name), nil
			}
			return value, nil
		},
	)

	// 9. 獲取檔案資訊
	genkit.DefineTool(
		g, "getFileInfo", "獲取檔案或目錄的詳細資訊",
		func(ctx *ai.ToolContext, input struct {
			Path string `json:"path" jsonschema_description:"檔案或目錄路徑"`
		},
		) (string, error) {
			// 路徑安全驗證
			safePath, err := pathValidator.ValidatePath(input.Path)
			if err != nil {
				return "", fmt.Errorf("路徑驗證失敗: %w", err)
			}

			info, err := os.Stat(safePath)
			if err != nil {
				return "", fmt.Errorf("無法獲取檔案資訊: %w", err)
			}

			result := fmt.Sprintf("名稱: %s\n", info.Name())
			result += fmt.Sprintf("大小: %d bytes\n", info.Size())
			result += fmt.Sprintf("是否為目錄: %v\n", info.IsDir())
			result += fmt.Sprintf("修改時間: %s\n", info.ModTime().Format("2006-01-02 15:04:05"))
			result += fmt.Sprintf("權限: %s\n", info.Mode().String())

			return result, nil
		},
	)
}
