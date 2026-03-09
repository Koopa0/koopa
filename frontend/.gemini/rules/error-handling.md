# 錯誤處理規範

處理優先順序：預防 > 處理、局部 > 全域、使用者體驗 > 技術細節

## HTTP 狀態碼處理

| 狀態碼 | 處理層 | 動作 |
|--------|--------|------|
| 401 | authInterceptor | 登出 + 導向 `/login` |
| 403 | errorInterceptor | 導向 `/unauthorized` |
| 404 | 元件層 | 顯示「找不到」或導向 404 頁 |
| 422 | 元件層 | 顯示欄位驗證錯誤 |
| 429 | errorInterceptor | 「請求過於頻繁」通知 |
| 500/502/503/504 | errorInterceptor | 「伺服器錯誤」通知 |
| 0 (網路) | errorInterceptor | 「網路連線失敗」通知 |

## 使用者訊息

禁止暴露技術細節（`ERR_CONNECTION_REFUSED`、`404 Not Found`、`Internal Server Error`）。
必須顯示友善中文訊息。

## 禁令

- 未處理的 Promise rejection（所有 async 必須 try-catch）
- 未處理的 Observable 錯誤（必須有 error handler 或 catchError）
- 生產環境暴露技術細節
- 忽略 `HttpErrorResponse`

## 檢查清單

- [ ] GlobalErrorHandler 已設定
- [ ] HTTP 錯誤由 errorInterceptor 統一處理
- [ ] 元件層處理 422 驗證錯誤
- [ ] 所有 Promise/Observable 有錯誤處理
- [ ] 錯誤訊息不洩露敏感資訊
