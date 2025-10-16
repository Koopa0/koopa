# Koopa

> 終端 AI 個人助理

Koopa 是一個基於 [Genkit](https://github.com/firebase/genkit) 的終端 AI 助手，讓你在命令列就能直接跟 AI 對話，處理各種任務。

## 核心特色

### AI 能力

- 🔄 **Streaming 即時回應** - 逐字顯示 AI 回應，打字機效果，提升互動體驗
- 📝 **結構化輸出** - 支援 JSON 結構化資料輸出（Zod schema 驗證）
- 🖼️ **多模態輸入** - 支援圖片分析、OCR、UI/UX 評估（JPEG/PNG/GIF/WebP）
- 💬 **會話管理** - 持久化對話歷史，支援多會話（檔案存儲）

### Genkit 完整整合

- 🔌 **MCP 協議** - 連接外部工具伺服器，暴露為 MCP server（client & server）
- ⚡ **8 個 AI Flows** - 預定義工作流程：程式碼審查、日誌分析、檔案分析、錯誤診斷等
- 🔍 **RAG 檢索** - 向量嵌入（text-embedding-004）與語義搜尋（餘弦相似度）
- 🔧 **9 個本地工具** - 檔案操作、系統命令、HTTP 請求、環境變數等
- 🎯 **Dotprompt** - 靈活的 prompt 管理系統（koopa_system.prompt）
- 📊 **Observability** - 內建 OpenTelemetry tracing 和 metrics

## 快速開始

### 安裝需求

- Go 1.25+
- Gemini API Key（[申請連結](https://ai.google.dev/)）

### 編譯執行

```bash
# 1. Clone 專案
git clone https://github.com/koopa0/koopa.git
cd koopa

# 2. 編譯
go build -o koopa

# 3. 設定 API Key
export GEMINI_API_KEY=your-api-key-here

# 4. 開始使用
./koopa
```

## 使用方式

### 互動對話（最常用）

直接執行 `koopa` 進入對話模式：

```bash
$ ./koopa
🐢 Koopa v0.1.0 - 你的終端 AI 個人助理
💡 輸入 /help 查看命令，Ctrl+D 或 /exit 退出

You> 你好
Koopa> 你好！有什麼我可以幫忙的嗎？

You> /tools
🔧 工具已啟用
   可用工具：
   - currentTime     獲取當前時間
   - readFile        讀取檔案
   - writeFile       寫入檔案
   - listFiles       列出目錄
   - deleteFile      刪除檔案
   - executeCommand  執行系統命令
   - httpGet         HTTP GET 請求
   - getEnv          讀取環境變數
   - getFileInfo     獲取檔案資訊

You> 現在幾點？
Koopa> 現在是 2025 年 10 月 16 日下午 12 點 30 分。

You> /exit
👋 再見！
```

#### 對話模式特殊命令

- `/help` - 顯示幫助訊息
- `/tools` - 切換工具啟用/禁用
- `/clear` - 清除對話歷史
- `/exit` 或 `/quit` - 退出對話
- `Ctrl+D` - 退出

### 單次問答

不進入對話模式，直接提問：

```bash
# 基本問答
./koopa ask "用一句話解釋什麼是 Go 語言"

# 使用工具
./koopa ask --tools "讀取 README.md 並總結重點"
./koopa ask --tools "現在幾點？"
```

### 使用 Genkit Flows

Koopa 提供 8 個預定義的 AI 工作流程，使用 Genkit CLI 執行：

```bash
# 啟動 Genkit Developer UI
genkit start -- go run main.go

# 執行 Flow（互動模式）
genkit flow:run chat '"你好"' -s                    # 流式對話
genkit flow:run analyzeFile '{"file_path": "main.go"}'  # 檔案分析
genkit flow:run reviewCode '"internal/agent/agent.go"'  # 程式碼審查
genkit flow:run analyzeLogs '"app.log"'                  # 日誌分析
genkit flow:run summarizeDocument '"README.md"'          # 文件摘要
genkit flow:run suggestCommand '"列出所有Go檔案"'       # 命令建議
genkit flow:run generateCommitMessage '"git diff內容"'  # Git提交訊息
genkit flow:run diagnoseError '"error: not found"'       # 錯誤診斷
```

### 查看資訊

```bash
# 查看版本和配置
./koopa version

# 查看所有 Flows
genkit flow:list
```

## 配置

### 環境變數（推薦）

```bash
export GEMINI_API_KEY=your-api-key-here
```

### 配置檔案（選用）

建立 `~/.koopa/config.yaml`：

```yaml
# AI 模型設定
model_name: "gemini-2.5-flash"
temperature: 0.7
max_tokens: 2048
# 資料庫路徑（預設為 ~/.koopa/koopa.db）
# database_path: "/path/to/koopa.db"

# API Key（建議用環境變數）
# gemini_api_key: "your-api-key-here"
```

## 專案架構

```
koopa/
├── cmd/                    # CLI 命令
│   ├── root.go            # 主命令
│   ├── chat.go            # 對話模式（含逐字 streaming）
│   ├── ask.go             # 單次問答
│   └── version.go         # 版本資訊
├── internal/
│   ├── agent/             # AI Agent 核心
│   │   ├── agent.go       # 主要邏輯與 Genkit 初始化
│   │   ├── tools.go       # 工具定義（9個工具）
│   │   ├── flows.go       # Genkit Flows（8個flows）
│   │   ├── mcp.go         # MCP 整合（client & server）
│   │   ├── session.go     # 會話管理與持久化
│   │   ├── rag.go         # RAG（Embedders & Retrievers）
│   │   └── multimodal.go  # 多模態輸入（圖片分析）
│   └── config/            # 配置管理
├── prompts/               # Dotprompt 檔案
│   └── koopa_system.prompt # System prompt 定義
├── main.go                # 程式進入點
├── DESIGN.md              # 設計文檔
├── GENKIT_FEATURES.md     # Genkit 功能整合詳解
└── config.example.yaml    # 配置範例
```

## 技術棧

- **語言**：Go 1.25+
- **AI 框架**：Genkit Go 1.1.0
- **CLI 框架**：Cobra
- **配置管理**：Viper
- **AI 模型**：Google Gemini 2.5 Flash

## 開發

```bash
# 執行代碼檢查
go vet ./...
staticcheck ./...
golangci-lint run

# 編譯
go build -o koopa

# 執行
./koopa
```

## 參考文檔

- [Genkit Go 官方文檔](https://firebase.google.com/docs/genkit/go)
- [MCP 協議規範](https://modelcontextprotocol.io/)

## 授權

MIT

## 聯絡

有問題或建議歡迎開 Issue。

---

**Phase 1 完成日期**：2025-10-16
**狀態**：✅ 生產就緒（建議替換開發級組件後部署）
