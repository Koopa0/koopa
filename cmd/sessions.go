package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/koopa0/koopa/internal/database"
	"github.com/koopa0/koopa/internal/memory"
	"github.com/spf13/cobra"
)

var sessionsCmd = &cobra.Command{
	Use:   "sessions",
	Short: "管理對話會話",
	Long:  `列出、查看或刪除已保存的對話會話`,
}

var sessionsListCmd = &cobra.Command{
	Use:   "list",
	Short: "列出所有會話",
	RunE:  runSessionsList,
}

var sessionsShowCmd = &cobra.Command{
	Use:   "show <session-id>",
	Short: "查看特定會話的訊息",
	Args:  cobra.ExactArgs(1),
	RunE:  runSessionsShow,
}

var sessionsDeleteCmd = &cobra.Command{
	Use:   "delete <session-id>",
	Short: "刪除特定會話",
	Args:  cobra.ExactArgs(1),
	RunE:  runSessionsDelete,
}

func init() {
	rootCmd.AddCommand(sessionsCmd)
	sessionsCmd.AddCommand(sessionsListCmd)
	sessionsCmd.AddCommand(sessionsShowCmd)
	sessionsCmd.AddCommand(sessionsDeleteCmd)
}

func runSessionsList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// 開啟資料庫
	dbPath := ".koopa/koopa.db"
	sqlDB, err := database.Open(dbPath)
	if err != nil {
		return fmt.Errorf("開啟資料庫失敗: %w", err)
	}
	defer sqlDB.Close()

	// 創建 memory 實例
	mem := memory.New(sqlDB)

	// 列出所有會話
	sessions, err := mem.ListSessions(ctx, 100) // 最多顯示 100 個
	if err != nil {
		return fmt.Errorf("列出會話失敗: %w", err)
	}

	if len(sessions) == 0 {
		fmt.Println("目前沒有已保存的會話")
		return nil
	}

	// 使用 tabwriter 格式化輸出
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\t標題\t創建時間\t最後更新")
	fmt.Fprintln(w, "──\t────\t────────\t────────")

	for _, session := range sessions {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n",
			session.ID,
			session.Title,
			formatTime(session.CreatedAt),
			formatTime(session.UpdatedAt),
		)
	}

	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "警告：輸出可能不完整: %v\n", err)
	}
	return nil
}

func runSessionsShow(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// 解析 session ID
	sessionID, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("無效的會話 ID: %s", args[0])
	}

	// 開啟資料庫
	dbPath := ".koopa/koopa.db"
	sqlDB, err := database.Open(dbPath)
	if err != nil {
		return fmt.Errorf("開啟資料庫失敗: %w", err)
	}
	defer sqlDB.Close()

	// 創建 memory 實例
	mem := memory.New(sqlDB)

	// 獲取會話資訊
	session, err := mem.GetSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("獲取會話失敗: %w", err)
	}

	// 獲取會話的所有訊息
	messages, err := mem.GetMessages(ctx, sessionID, 0) // 0 = 所有訊息
	if err != nil {
		return fmt.Errorf("獲取訊息失敗: %w", err)
	}

	// 顯示會話資訊
	fmt.Printf("📝 會話 ID: %d\n", session.ID)
	fmt.Printf("📋 標題: %s\n", session.Title)
	fmt.Printf("🕐 創建時間: %s\n", formatTime(session.CreatedAt))
	fmt.Printf("🕐 最後更新: %s\n", formatTime(session.UpdatedAt))
	fmt.Printf("💬 訊息數量: %d\n", len(messages))
	fmt.Println()
	fmt.Println("───────────────────────────────────────")
	fmt.Println()

	// 顯示訊息
	for _, msg := range messages {
		role := "You"
		if msg.Role == "model" {
			role = "Koopa"
		}
		fmt.Printf("%s> %s\n", role, msg.Content)
		fmt.Println()
	}

	return nil
}

func runSessionsDelete(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// 解析 session ID
	sessionID, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("無效的會話 ID: %s", args[0])
	}

	// 開啟資料庫
	dbPath := ".koopa/koopa.db"
	sqlDB, err := database.Open(dbPath)
	if err != nil {
		return fmt.Errorf("開啟資料庫失敗: %w", err)
	}
	defer sqlDB.Close()

	// 創建 memory 實例
	mem := memory.New(sqlDB)

	// 刪除會話
	if err := mem.DeleteSession(ctx, sessionID); err != nil {
		return fmt.Errorf("刪除會話失敗: %w", err)
	}

	fmt.Printf("✅ 已刪除會話 %d\n", sessionID)
	return nil
}

// formatTime 格式化時間為易讀格式
func formatTime(t time.Time) string {
	now := time.Now()
	diff := now.Sub(t)

	switch {
	case diff < time.Minute:
		return "剛剛"
	case diff < time.Hour:
		return fmt.Sprintf("%d 分鐘前", int(diff.Minutes()))
	case diff < 24*time.Hour:
		return fmt.Sprintf("%d 小時前", int(diff.Hours()))
	case diff < 7*24*time.Hour:
		return fmt.Sprintf("%d 天前", int(diff.Hours()/24))
	default:
		return t.Format("2006-01-02 15:04")
	}
}
