package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "koopa",
	Short: "Koopa - 你的終端 AI 個人助理",
	Long: `Koopa 是一個基於 Genkit 的終端 AI 個人助理。
它能夠理解你的需求，記住對話內容，並透過工具幫助你完成各種任務。

直接執行 koopa 將進入互動式對話模式。`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// 無參數時進入 chat 模式
		return runChat(cmd, args)
	},
}

// Execute 執行根命令
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// 子命令已在各自的檔案中註冊
}
