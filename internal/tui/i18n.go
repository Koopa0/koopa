package tui

// toolDisplayNames maps tool names to localized display names.
var toolDisplayNames = map[string]string{
	"web_search":              "搜尋網路",
	"web_fetch":               "讀取網頁",
	"read_file":               "讀取檔案",
	"write_file":              "寫入檔案",
	"list_files":              "瀏覽目錄",
	"delete_file":             "刪除檔案",
	"get_file_info":           "取得檔案資訊",
	"execute_command":         "執行命令",
	"current_time":            "取得時間",
	"get_env":                 "取得環境變數",
	"search_history":          "搜尋對話記錄",
	"search_documents":        "搜尋知識庫",
	"search_system_knowledge": "搜尋系統知識",
	"knowledge_store":         "儲存知識",
}

// toolDisplayName returns a localized display name for a tool.
func toolDisplayName(name string) string {
	if display, ok := toolDisplayNames[name]; ok {
		return display
	}
	return name
}
