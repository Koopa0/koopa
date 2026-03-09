---
paths:
  - "src/app/core/interceptors/**"
  - "src/app/core/services/**"
  - "src/app/features/**/*.service.ts"
---

# HTTP 模式規範

> 完整程式碼範例見 `angular-http` skill。

## Interceptor 執行順序

```
Request:  logging -> auth -> csrf -> cache -> retry -> error -> HttpBackend
Response: logging <- auth <- csrf <- cache <- retry <- error <- HttpBackend
```

必須使用函式型 `HttpInterceptorFn`，禁止 class-based interceptor。

## Interceptor 職責

| Interceptor | 職責 | 適用請求 |
|-------------|------|---------|
| loggingInterceptor | 記錄請求時間（僅 devMode） | 所有 |
| authInterceptor | 加入 Bearer token | 需認證（跳過 `X-Skip-Auth`） |
| csrfInterceptor | 加入 CSRF token | POST/PUT/PATCH/DELETE |
| cacheInterceptor | GET 請求快取（TTL 5min） | GET（跳過 `X-Skip-Cache`） |
| retryInterceptor | 指數退避重試（max 3） | GET + 可重試狀態碼 |
| errorInterceptor | 統一錯誤處理與通知 | 所有（跳過 `X-Skip-Error-*`） |

## 重試策略

- 只重試 GET 請求（冪等操作）
- 可重試狀態碼：408, 429, 500, 502, 503, 504
- 指數退避：1s, 2s, 4s

## Service 層規則

- Service 使用 `Observable` 回傳
- 元件用 `firstValueFrom()` + try-catch 或 `toSignal()` + catchError
- 訂閱必須 `takeUntilDestroyed()` 清理
- 搜尋使用 `switchMap` 自動取消前一個請求

## API Response 標準格式

成功：`{ success: true, data: T, meta?: { page, pageSize, total, totalPages } }`
錯誤：`{ success: false, error: { code, message, details? } }`

## 檢查清單

- [ ] 函式型 Interceptor
- [ ] Auth Interceptor 正確加入 token
- [ ] Error Interceptor 統一處理
- [ ] Retry 只重試冪等操作
- [ ] Cache 只快取 GET
- [ ] CSRF 保護變更請求
- [ ] 訂閱 `takeUntilDestroyed` 清理
