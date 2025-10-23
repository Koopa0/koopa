package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/koopa0/koopa/internal/agent"
	"github.com/koopa0/koopa/internal/config"
	"github.com/spf13/cobra"
)

var chatCmd = &cobra.Command{
	Use:   "chat",
	Short: "進入互動式對話模式",
	Long: `與 Koopa 進行多輪對話。

特殊命令：
  /help    - 顯示幫助
  /tools   - 切換工具啟用/禁用
  /clear   - 清除對話歷史
  /exit    - 退出（或按 Ctrl+D）`,
	RunE: runChat,
}

func init() {
	rootCmd.AddCommand(chatCmd)
}

func runChat(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// 載入配置
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("載入配置失敗: %w", err)
	}

	// 檢查 API Key
	if cfg.GeminiAPIKey == "" {
		fmt.Fprintln(os.Stderr, "❌ 錯誤：未設定 KOOPA_GEMINI_API_KEY 環境變數")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "請執行：")
		fmt.Fprintln(os.Stderr, "  export KOOPA_GEMINI_API_KEY=your-api-key")
		return fmt.Errorf("KOOPA_GEMINI_API_KEY not set")
	}

	// 創建 Agent
	ag, err := agent.New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("創建 Agent 失敗: %w", err)
	}

	// 顯示歡迎訊息
	fmt.Println("🐢 Koopa v0.1.0 - 你的終端 AI 個人助理")
	fmt.Println("💡 輸入 /help 查看命令，Ctrl+D 或 /exit 退出")
	fmt.Println()

	// 開始對話循環
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("You> ")

		// 讀取用戶輸入
		if !scanner.Scan() {
			// EOF (Ctrl+D)
			fmt.Println("\n👋 再見！")
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		// 處理特殊命令
		if strings.HasPrefix(input, "/") {
			if handleCommand(input, ag) {
				break // 退出命令
			}
			continue
		}

		// 發送訊息給 AI（使用 streaming）
		fmt.Print("Koopa> ")
		_ = os.Stdout.Sync() // 確保提示符立即顯示

		_, err := ag.ChatStream(ctx, input, func(chunk string) {
			// 逐字輸出，模擬打字機效果
			printCharByChar(chunk)
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n❌ 錯誤: %v\n", err)
			continue
		}
		fmt.Println()
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return fmt.Errorf("讀取輸入失敗: %w", err)
	}

	return nil
}

// handleCommand 處理特殊命令，返回 true 表示應該退出
func handleCommand(cmd string, ag *agent.Agent) bool {
	switch cmd {
	case "/help":
		fmt.Println("可用命令：")
		fmt.Println("  /help    - 顯示此幫助訊息")
		fmt.Println("  /tools   - 切換工具啟用/禁用")
		fmt.Println("  /clear   - 清除對話歷史")
		fmt.Println("  /exit    - 退出對話")
		fmt.Println()

	case "/tools":
		currentState := ag.GetToolsEnabled()
		ag.SetTools(!currentState)
		if ag.GetToolsEnabled() {
			fmt.Println("🔧 工具已啟用")
			fmt.Println("   可用工具：")
			fmt.Println("   - currentTime     獲取當前時間")
			fmt.Println("   - readFile        讀取檔案")
			fmt.Println("   - writeFile       寫入檔案")
			fmt.Println("   - listFiles       列出目錄")
			fmt.Println("   - deleteFile      刪除檔案")
			fmt.Println("   - executeCommand  執行系統命令")
			fmt.Println("   - httpGet         HTTP GET 請求")
			fmt.Println("   - getEnv          讀取環境變數")
			fmt.Println("   - getFileInfo     獲取檔案資訊")
		} else {
			fmt.Println("🔧 工具已禁用")
		}
		fmt.Println()

	case "/clear":
		ag.ClearHistory()
		fmt.Println("🧹 對話歷史已清除")
		fmt.Println()

	case "/exit", "/quit":
		fmt.Println("👋 再見！")
		return true

	default:
		fmt.Printf("❌ 未知命令: %s\n", cmd)
		fmt.Println("💡 輸入 /help 查看可用命令")
		fmt.Println()
	}

	return false
}

// printCharByChar 逐字輸出文本，模擬打字機效果
func printCharByChar(text string) {
	// 遍歷每個 UTF-8 字符（而不是字節）
	for len(text) > 0 {
		r, size := utf8.DecodeRuneInString(text)
		fmt.Print(string(r))
		_ = os.Stdout.Sync() // 立即 flush

		// 添加微小延遲，製造打字機效果
		// 中文字符稍慢，英文字符稍快
		if r > 127 { // 非 ASCII 字符（如中文）
			time.Sleep(30 * time.Millisecond)
		} else if r == ' ' || r == '\n' {
			// 空格和換行符不延遲
			time.Sleep(5 * time.Millisecond)
		} else {
			time.Sleep(20 * time.Millisecond)
		}

		text = text[size:]
	}
}
