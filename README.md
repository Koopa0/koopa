# Koopa

> 終端 AI 個人助理

Koopa 是一個基於 [Genkit](https://github.com/firebase/genkit) 的終端 AI 助手，讓你在命令列就能直接跟 AI 對話，處理各種任務。

## 核心特色

### 部署優勢

- **100% 純 Go** - 無 CGO 依賴，單一靜態二進制文件
- **輕鬆跨平台** - 一條命令編譯 Linux/Windows/macOS/ARM
- **零環境要求** - 無需安裝 C 編譯器或任何依賴
- **即下即用** - 下載即可執行，完美符合 Go 哲學

### AI 能力

- **Streaming 即時回應** - 逐字顯示 AI 回應，打字機效果，提升互動體驗
- **結構化輸出** - 支援 JSON 結構化資料輸出（Zod schema 驗證）
- **多模態輸入** - 支援圖片分析、OCR、UI/UX 評估（JPEG/PNG/GIF/WebP）
- **會話管理** - 持久化對話歷史，支援多會話（純 Go SQLite）

### Genkit 完整整合

- **MCP 協議** - 連接外部工具伺服器，暴露為 MCP server（client & server）
- **8 個 AI Flows** - 預定義工作流程：程式碼審查、日誌分析、檔案分析、錯誤診斷等
- **RAG 檢索** - 向量嵌入（text-embedding-004）與語義搜尋（餘弦相似度）
- **9 個本地工具** - 檔案操作、系統命令（含安全檢查）、HTTP 請求、環境變數等
- **Dotprompt** - 靈活的 prompt 管理系統（koopa_system.prompt）
- **Observability** - 內建 OpenTelemetry tracing 和 metrics

## 快速開始

### 安裝需求

- Go 1.25+
- Gemini API Key（[申請連結](https://ai.google.dev/)）

### 編譯執行

```bash
# 1. Clone 專案
git clone https://github.com/koopa0/koopa.git
cd koopa

# 2. 編譯（100% 純 Go，無 CGO）
go build -o koopa

# 3. 設定 API Key
export KOOPA_GEMINI_API_KEY=your-api-key-here

# 4. 開始使用
./koopa
```

### 跨平台編譯

無需任何交叉編譯工具，一條命令即可：

```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o koopa-linux-amd64

# Windows AMD64
GOOS=windows GOARCH=amd64 go build -o koopa-windows-amd64.exe

# Linux ARM64 (Raspberry Pi 等)
GOOS=linux GOARCH=arm64 go build -o koopa-linux-arm64

# macOS ARM64 (M1/M2/M3)
GOOS=darwin GOARCH=arm64 go build -o koopa-darwin-arm64
```

## 使用方式

### 互動對話（最常用）

直接執行 `koopa` 進入對話模式：

```bash
$ ./koopa
Koopa v0.1.0 - 你的終端 AI 個人助理
輸入 /help 查看命令，Ctrl+D 或 /exit 退出

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
再見！
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

使用 `KOOPA_` 前綴避免命名衝突：

```bash
export KOOPA_GEMINI_API_KEY=your-api-key-here
export KOOPA_MODEL_NAME=gemini-2.5-pro      # 可選
export KOOPA_TEMPERATURE=0.8                 # 可選
export KOOPA_MAX_TOKENS=4096                 # 可選
export KOOPA_MAX_HISTORY_MESSAGES=100        # 可選
```

**環境變數優先級**：`KOOPA_*` > 配置檔案 > 預設值

### 配置檔案（選用）

建立 `~/.koopa/config.yaml`：

```yaml
# AI 模型設定
model_name: "gemini-2.5-flash"
temperature: 0.7
max_tokens: 2048

# 對話歷史配置（預設 50 則，約 25 輪對話）
# 啟用滑動窗口機制，防止 token 消耗過高
max_history_messages: 50

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

- **語言**：Go 1.25+ (100% 純 Go，無 CGO)
- **AI 框架**：Genkit Go 1.1.0
- **CLI 框架**：Cobra
- **配置管理**：Viper
- **資料庫**：modernc.org/sqlite (純 Go SQLite)
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

## 更新日誌

### Phase 1.7 (2025-10-16)

**配置系統重構**：

1. **類型安全的配置載入**
   - 使用 `viper.Unmarshal` 替代手動賦值
   - 為 Config 結構體添加 `mapstructure` 標籤
   - 自動映射配置值到結構體，減少維護負擔

2. **環境變數命名空間**
   - 引入 `KOOPA_` 前綴避免全局環境變數衝突
   - 優先級：`KOOPA_*` > 配置檔案 > 預設值
   - 所有環境變數統一使用前綴

3. **明確的環境變數綁定**
   - 移除 `BindEnv` 歧義，採用顯式綁定策略
   - 支援所有配置項的環境變數覆蓋
   - 完整的環境變數列表文檔化

### Phase 1.6 (2025-10-16)

**重大改進 - 移除 CGO 依賴**：

1. **100% 純 Go 實現**
   - 將 `github.com/mattn/go-sqlite3` 替換為 `modernc.org/sqlite`
   - 完全移除 CGO 依賴，恢復 Go 的跨平台編譯優勢
   - 驗證通過：`CGO_ENABLED=0 go build` 編譯成功

2. **跨平台編譯簡化**
   - 無需 C 編譯器或交叉編譯工具鏈
   - 一條命令即可為任何平台編譯
   - 支援 Linux/Windows/macOS/ARM 等所有 Go 支援的平台

3. **部署體驗提升**
   - 單一靜態二進制文件，無依賴
   - 使用者無需安裝任何環境
   - 完美符合 Go 語言的設計哲學

### Phase 1.5 (2025-10-16)

**優化與改進**：

1. **對話歷史滑動窗口機制**
   - 預設保留最近 50 則訊息（約 25 輪對話）
   - 自動清理舊訊息，防止 token 消耗過高
   - 可透過 `max_history_messages` 配置調整

2. **executeCommand 安全檢查**
   - 自動檢測 13 種危險命令（rm, mkfs, dd, reboot 等）
   - 檢測 5 種高風險參數模式（-rf, --force 等）
   - 危險命令自動阻止，並提示用戶手動執行

3. **Flows 可組合性重構**
   - 提取共用檔案讀取邏輯 (`readFileWithLimit`)
   - 統一錯誤處理和大小限制
   - 日誌檔案智能取尾部，一般檔案取開頭

---
