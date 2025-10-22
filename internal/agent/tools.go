package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
)

// 危險命令黑名單（用於 executeCommand 安全檢查）
var dangerousCommands = map[string]string{
	"rm":       "刪除檔案（特別是 rm -rf 可能造成嚴重損害）",
	"mkfs":     "格式化磁碟（會清除所有資料）",
	"dd":       "直接寫入磁碟（可能覆蓋重要資料）",
	"fdisk":    "磁碟分割工具（可能損壞分割表）",
	"parted":   "磁碟分割工具（可能損壞分割表）",
	"shred":    "安全刪除檔案（不可恢復）",
	"wipefs":   "清除檔案系統簽名",
	"mkswap":   "建立 swap 空間（會覆蓋資料）",
	"reboot":   "重啟系統",
	"shutdown": "關閉系統",
	"init":     "改變系統運行級別",
	"halt":     "停止系統",
	"poweroff": "關閉電源",
}

// 高風險參數模式
var dangerousPatterns = []string{
	"-rf",      // rm -rf
	"--force",  // 強制執行
	"--no-preserve-root", // 允許刪除根目錄
	"/dev/",    // 直接操作設備
	"> /dev/",  // 重定向到設備
}

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
		}) (string, error) {
			content, err := os.ReadFile(input.Path)
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
		}) (string, error) {
			// 確保目錄存在
			dir := filepath.Dir(input.Path)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return "", fmt.Errorf("無法創建目錄: %w", err)
			}

			err := os.WriteFile(input.Path, []byte(input.Content), 0644)
			if err != nil {
				return "", fmt.Errorf("無法寫入檔案: %w", err)
			}
			return fmt.Sprintf("成功寫入檔案: %s", input.Path), nil
		},
	)

	// 4. 列出目錄內容
	genkit.DefineTool(
		g, "listFiles", "列出目錄中的檔案和子目錄",
		func(ctx *ai.ToolContext, input struct {
			Path string `json:"path" jsonschema_description:"要列出的目錄路徑"`
		}) (string, error) {
			entries, err := os.ReadDir(input.Path)
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
		}) (string, error) {
			err := os.Remove(input.Path)
			if err != nil {
				return "", fmt.Errorf("無法刪除檔案: %w", err)
			}
			return fmt.Sprintf("成功刪除檔案: %s", input.Path), nil
		},
	)

	// 6. 執行系統命令
	genkit.DefineTool(
		g, "executeCommand", "執行系統命令（謹慎使用，會自動檢查危險命令）",
		func(ctx *ai.ToolContext, input struct {
			Command string   `json:"command" jsonschema_description:"要執行的命令"`
			Args    []string `json:"args,omitempty" jsonschema_description:"命令參數（可選）"`
		}) (string, error) {
			// 安全檢查：檢查是否為危險命令
			if reason, isDangerous := isDangerousCommand(input.Command, input.Args); isDangerous {
				return "", fmt.Errorf("⚠️  安全警告：拒絕執行危險命令\n命令: %s %s\n原因: %s\n如需執行，請使用者手動在終端執行",
					input.Command, strings.Join(input.Args, " "), reason)
			}

			cmd := exec.Command(input.Command, input.Args...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				return "", fmt.Errorf("命令執行失敗: %w\n輸出: %s", err, string(output))
			}
			return string(output), nil
		},
	)

	// 7. HTTP GET 請求
	genkit.DefineTool(
		g, "httpGet", "發送 HTTP GET 請求",
		func(ctx *ai.ToolContext, input struct {
			URL string `json:"url" jsonschema_description:"要請求的 URL"`
		}) (string, error) {
			resp, err := http.Get(input.URL)
			if err != nil {
				return "", fmt.Errorf("HTTP 請求失敗: %w", err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return "", fmt.Errorf("讀取回應失敗: %w", err)
			}

			result := map[string]interface{}{
				"status": resp.StatusCode,
				"body":   string(body),
			}

			jsonResult, _ := json.Marshal(result)
			return string(jsonResult), nil
		},
	)

	// 8. 讀取環境變數
	genkit.DefineTool(
		g, "getEnv", "讀取環境變數",
		func(ctx *ai.ToolContext, input struct {
			Name string `json:"name" jsonschema_description:"環境變數名稱"`
		}) (string, error) {
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
		}) (string, error) {
			info, err := os.Stat(input.Path)
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

// isDangerousCommand 檢查命令是否為危險命令
// 返回 (原因, 是否危險)
func isDangerousCommand(command string, args []string) (string, bool) {
	// 提取命令的基本名稱（去除路徑）
	cmdBase := filepath.Base(command)

	// 檢查是否在黑名單中
	if reason, exists := dangerousCommands[cmdBase]; exists {
		return reason, true
	}

	// 檢查參數中是否包含危險模式
	allArgs := strings.Join(args, " ")
	for _, pattern := range dangerousPatterns {
		if strings.Contains(allArgs, pattern) {
			return fmt.Sprintf("參數包含危險模式: %s", pattern), true
		}
	}

	return "", false
}
