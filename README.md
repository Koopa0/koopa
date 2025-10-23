# Koopa

> 終端 AI 個人助理

Koopa 是一個基於 [Genkit](https://github.com/firebase/genkit) 的終端 AI 助手，讓你在命令列就能直接跟 AI 對話，處理各種任務

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
- **9 個 AI Flows** - Personal AI Assistant 工作流程：對話、分析、郵件撰寫、主題研究、任務規劃、程式碼審查等
- **RAG 檢索** - 向量嵌入（text-embedding-004）與語義搜尋（餘弦相似度）
- **9 個本地工具** - 檔案操作、系統命令（含安全檢查）、HTTP 請求、環境變數等
- **Dotprompt** - 靈活的 prompt 管理系統（koopa.prompt）
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

Koopa 提供 9 個預定義的 AI 工作流程，涵蓋對話、內容創作、研究、生產力、開發輔助等領域：

```bash
# 啟動 Genkit Developer UI
genkit start -- go run main.go

# 核心通用
genkit flow:run chat '"你好"' -s                                              # 流式對話

# 分析類（統一入口，支援 file/log/document/text）
genkit flow:run analyze '{"content":"main.go","content_type":"file"}'        # 檔案分析
genkit flow:run analyze '{"content":"app.log","content_type":"log"}'         # 日誌分析
genkit flow:run analyze '{"content":"README.md","content_type":"document"}'  # 文件分析

# 內容創作
genkit flow:run composeEmail '{"recipient":"同事","purpose":"thanks","context":"協助專案開發"}'

# 研究與資訊
genkit flow:run researchTopic '{"topic":"Genkit 框架最佳實踐"}'

# 生產力
genkit flow:run planTasks '{"goal":"完成 API 開發","deadline":"本週五"}'

# 開發輔助
genkit flow:run reviewCode '"internal/agent/agent.go"'
genkit flow:run suggestCommand '"列出所有Go檔案"'
genkit flow:run generateCommitMessage '"git diff內容"'
genkit flow:run diagnoseError '"error: not found"'
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

## 參考文檔

- [Genkit Go 官方文檔](https://firebase.google.com/docs/genkit/go)
- [MCP 協議規範](https://modelcontextprotocol.io/)

## 授權

MIT

## 聯絡

有問題或建議歡迎開 Issue。

---
