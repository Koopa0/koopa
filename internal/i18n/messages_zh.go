package i18n

// loadChineseMessages loads all Traditional Chinese translations
func loadChineseMessages() {
	messages[LangZhTW] = map[string]string{
		// Common
		"app.name":        "Koopa",
		"app.description": "您的終端 AI 個人助理",
		"app.version":     "Koopa v%s",

		// Welcome and Exit
		"welcome":      "歡迎使用 Koopa v%s - 您的終端 AI 個人助理",
		"welcome.help": "輸入 /help 查看命令，Ctrl+D 或 /exit 退出",
		"goodbye":      "再見！",
		"exit":         "正在退出...",

		// Chat commands
		"chat.prompt":          "您> ",
		"chat.assistant":       "Koopa> ",
		"chat.tools.enabled":   "🔧 工具已啟用",
		"chat.tools.disabled":  "🔧 工具已停用",
		"chat.tools.available": "   可用工具：",
		"chat.tool.item":       "   - %-15s %s",
		"chat.cleared":         "✨ 聊天記錄已清除",
		"chat.streaming.error": "串流錯誤：%v",

		// Help messages
		"help.title":          "可用命令：",
		"help.help":           "/help              顯示此幫助訊息",
		"help.tools":          "/tools             切換工具開關",
		"help.clear":          "/clear             清除聊天記錄",
		"help.exit":           "/exit 或 /quit     退出聊天",
		"help.lang":           "/lang <code>       切換語言 (en, zh-TW)",
		"help.ctrl_d":         "Ctrl+D             退出聊天",
		"help.current.lang":   "\n目前語言：%s",
		"help.available.lang": "可用語言：%s",

		// Language
		"lang.changed":     "語言已切換為：%s",
		"lang.unsupported": "不支援的語言：%s",
		"lang.available":   "可用語言：%s",
		"lang.current":     "目前語言：%s",

		// Errors
		"error.input":          "讀取輸入時發生錯誤：%v",
		"error.generate":       "生成回應時發生錯誤：%v",
		"error.config":         "載入配置時發生錯誤：%v",
		"error.agent":          "建立代理時發生錯誤：%v",
		"error.memory":         "初始化記憶體時發生錯誤：%v",
		"error.database":       "初始化資料庫時發生錯誤：%v",
		"error.session":        "建立會話時發生錯誤：%v",
		"error.message":        "儲存訊息時發生錯誤：%v",
		"error.question.empty": "問題不能為空",

		// Session management
		"session.list.title":  "可用會話：",
		"session.list.item":   "  [%d] %s（建立時間：%s，更新時間：%s）",
		"session.list.empty":  "找不到會話",
		"session.delete.ok":   "會話 %d 已成功刪除",
		"session.delete.fail": "刪除會話失敗：%v",

		// Ask command
		"ask.description": "向 Koopa 提出單一問題",
		"ask.question":    "要詢問的問題",
		"ask.tools.flag":  "為此問題啟用工具",

		// Chat command
		"chat.description":      "啟動與 Koopa 的互動式聊天會話",
		"chat.session.flag":     "要繼續的會話 ID（可選）",
		"chat.tools.flag":       "預設啟用工具",
		"chat.session.creating": "正在建立新會話...",
		"chat.session.loading":  "正在載入會話 %d...",

		// Sessions command
		"sessions.description":        "管理聊天會話",
		"sessions.list.description":   "列出所有會話",
		"sessions.delete.description": "刪除會話",
		"sessions.delete.id":          "要刪除的會話 ID",

		// Version command
		"version.description": "顯示版本資訊",
		"version.info":        "Koopa v%s\n建置日期：%s\nGit 提交：%s",

		// Config
		"config.model":       "模型：%s",
		"config.temperature": "溫度：%.2f",
		"config.max.tokens":  "最大標記數：%d",

		// Tool names and descriptions (from tools.go)
		"tool.currentTime.name":       "currentTime",
		"tool.currentTime.desc":       "取得目前時間",
		"tool.readFile.name":          "readFile",
		"tool.readFile.desc":          "讀取檔案內容",
		"tool.writeFile.name":         "writeFile",
		"tool.writeFile.desc":         "將內容寫入檔案",
		"tool.listFiles.name":         "listFiles",
		"tool.listFiles.desc":         "列出目錄內容",
		"tool.deleteFile.name":        "deleteFile",
		"tool.deleteFile.desc":        "刪除檔案",
		"tool.executeCommand.name":    "executeCommand",
		"tool.executeCommand.desc":    "執行系統命令",
		"tool.httpGet.name":           "httpGet",
		"tool.httpGet.desc":           "HTTP GET 請求",
		"tool.getEnv.name":            "getEnv",
		"tool.getEnv.desc":            "讀取環境變數",
		"tool.getFileInfo.name":       "getFileInfo",
		"tool.getFileInfo.desc":       "取得檔案資訊",

		// Security warnings (from security validators)
		"security.path.invalid":      "⚠️  安全警告：路徑驗證失敗\n原因：%w",
		"security.command.dangerous": "⚠️  安全警告：已拒絕危險命令\n命令：%s %s\n原因：%w\n如需執行此操作，請在終端中手動執行",
		"security.url.invalid":       "⚠️  安全警告：URL 驗證失敗\n原因：%w\n這可能是嘗試存取內部網路或元資料服務",
		"security.env.restricted":    "⚠️  安全警告：%w\n提示：此環境變數可能包含敏感資訊並受到保護。\n如需存取，請直接在終端中檢查",

		// Root command
		"root.description": "Koopa - 基於 Genkit 的終端 AI 個人助理",
		"root.lang.flag":   "語言（en、zh-TW）",
	}
}
