// Package handlers provides HTTP request handlers for the web server.
package handlers

// toolDisplayInfo contains UI presentation data for a tool.
// Per architecture-master: All UI concerns centralized here for i18n support.
type toolDisplayInfo struct {
	StartMsg    string // Message shown when tool starts (e.g., "搜尋網路中...")
	CompleteMsg string // Message shown when tool completes (e.g., "搜尋完成")
	ErrorMsg    string // User-friendly error message (no internal details)
}

// toolDisplay maps tool names to UI presentation.
// Tool names use snake_case matching tools.Tool* constants.
// Per ui-master: All messages in Chinese for target user base.
var toolDisplay = map[string]toolDisplayInfo{
	// Network tools
	"web_search": {
		StartMsg:    "搜尋網路中...",
		CompleteMsg: "搜尋完成",
		ErrorMsg:    "搜尋服務暫時無法使用，請稍後再試",
	},
	"web_fetch": {
		StartMsg:    "讀取網頁中...",
		CompleteMsg: "已讀取內容",
		ErrorMsg:    "無法讀取網頁內容",
	},

	// File tools
	"read_file": {
		StartMsg:    "讀取檔案中...",
		CompleteMsg: "已讀取檔案",
		ErrorMsg:    "無法讀取檔案",
	},
	"write_file": {
		StartMsg:    "寫入檔案中...",
		CompleteMsg: "已寫入檔案",
		ErrorMsg:    "寫入檔案失敗",
	},
	"list_files": {
		StartMsg:    "瀏覽目錄中...",
		CompleteMsg: "目錄瀏覽完成",
		ErrorMsg:    "無法瀏覽目錄",
	},
	"delete_file": {
		StartMsg:    "刪除檔案中...",
		CompleteMsg: "已刪除檔案",
		ErrorMsg:    "刪除檔案失敗",
	},
	"get_file_info": {
		StartMsg:    "取得檔案資訊中...",
		CompleteMsg: "已取得檔案資訊",
		ErrorMsg:    "無法取得檔案資訊",
	},

	// System tools
	"execute_command": {
		StartMsg:    "執行命令中...",
		CompleteMsg: "命令執行完成",
		ErrorMsg:    "命令執行失敗",
	},
	"current_time": {
		StartMsg:    "取得時間中...",
		CompleteMsg: "時間已取得",
		ErrorMsg:    "無法取得時間",
	},
	"get_env": {
		StartMsg:    "取得環境變數中...",
		CompleteMsg: "環境變數已取得",
		ErrorMsg:    "無法取得環境變數",
	},

	// Knowledge tools
	"knowledge_search": {
		StartMsg:    "搜尋知識庫中...",
		CompleteMsg: "知識庫搜尋完成",
		ErrorMsg:    "無法搜尋知識庫",
	},
	"knowledge_store": {
		StartMsg:    "儲存至知識庫中...",
		CompleteMsg: "已儲存至知識庫",
		ErrorMsg:    "無法儲存至知識庫",
	},
}

// defaultDisplay is used for unknown tools.
var defaultDisplay = toolDisplayInfo{
	StartMsg:    "執行工具中...",
	CompleteMsg: "工具執行完成",
	ErrorMsg:    "工具執行失敗",
}

// getToolDisplay returns UI info for a tool, with fallback to default.
// Per architecture-master: Single lookup point for all tool UI data.
func getToolDisplay(name string) toolDisplayInfo {
	if info, ok := toolDisplay[name]; ok {
		return info
	}
	return defaultDisplay
}
