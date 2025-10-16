package cmd

import (
	"fmt"

	"github.com/koopa0/koopa/internal/config"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "顯示版本資訊和配置狀態",
	RunE:  runVersion,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func runVersion(cmd *cobra.Command, args []string) error {
	fmt.Println("Koopa v0.1.0-alpha (Phase 1 開發中)")
	fmt.Println()

	// 載入配置
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("載入配置失敗: %w", err)
	}

	// 顯示配置資訊
	fmt.Println("配置資訊：")
	fmt.Printf("  模型: %s\n", cfg.ModelName)
	fmt.Printf("  Temperature: %.1f\n", cfg.Temperature)
	fmt.Printf("  Max Tokens: %d\n", cfg.MaxTokens)
	fmt.Printf("  資料庫: %s\n", cfg.DatabasePath)

	// 檢查 API Key（不顯示完整內容）
	if cfg.GeminiAPIKey != "" {
		fmt.Printf("  Gemini API Key: %s...%s (已設定)\n",
			cfg.GeminiAPIKey[:4],
			cfg.GeminiAPIKey[len(cfg.GeminiAPIKey)-4:])
	} else {
		fmt.Println("  Gemini API Key: ⚠️  未設定")
		fmt.Println()
		fmt.Println("提示：請設定 GEMINI_API_KEY 環境變數")
		fmt.Println("  export GEMINI_API_KEY=your-api-key")
	}

	return nil
}
