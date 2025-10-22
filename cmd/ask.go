package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/koopa0/koopa/internal/agent"
	"github.com/koopa0/koopa/internal/config"
	"github.com/spf13/cobra"
)

var (
	useTools bool
)

var askCmd = &cobra.Command{
	Use:   "ask [question]",
	Short: "向 Koopa 提問",
	Long: `向 Koopa 提出單一問題並獲得回應。

範例：
  koopa ask "什麼是 Go 語言？"
  koopa ask "今天天氣如何？"
  koopa ask --tools "現在幾點？"
  koopa ask --tools "讀取 README.md 檔案內容"`,
	Args: cobra.MinimumNArgs(1),
	RunE: runAsk,
}

func init() {
	askCmd.Flags().BoolVar(&useTools, "tools", false, "啟用工具調用（currentTime, readFile, executeCommand 等）")
	rootCmd.AddCommand(askCmd)
}

func runAsk(cmd *cobra.Command, args []string) error {
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

	// 合併所有參數作為問題
	question := strings.Join(args, " ")

	fmt.Printf("🤔 正在思考：%s\n", question)
	if useTools {
		fmt.Println("🔧 已啟用 9 個工具（currentTime, readFile, writeFile, listFiles, deleteFile, executeCommand, httpGet, getEnv, getFileInfo）")
	}
	fmt.Println()

	// 向 AI 提問
	var answer string
	if useTools {
		answer, err = ag.AskWithTools(ctx, question)
	} else {
		answer, err = ag.Ask(ctx, question)
	}
	if err != nil {
		return fmt.Errorf("提問失敗: %w", err)
	}

	// 顯示回應
	fmt.Println(answer)

	return nil
}
