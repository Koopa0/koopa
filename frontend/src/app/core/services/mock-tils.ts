import { TilEntry } from '../models/til.model';

export const MOCK_TILS: TilEntry[] = [
  {
    id: 'til-001',
    slug: 'go-context-timeout',
    title: 'Go context.WithTimeout 會自動取消子 goroutine',
    content:
      '今天才發現 `context.WithTimeout` 建立的 context，當 timeout 到達時會自動呼叫 cancel，所有監聽這個 context 的 goroutine 都會收到取消信號。不需要手動呼叫 cancel（但仍然建議 defer cancel）。',
    codeSnippet: `ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel() // 即使 timeout 會自動 cancel，仍建議 defer

go func() {
    select {
    case <-ctx.Done():
        fmt.Println("cancelled:", ctx.Err())
    case result := <-doWork(ctx):
        fmt.Println("result:", result)
    }
}()`,
    codeLanguage: 'go',
    tags: ['Golang'],
    publishedAt: new Date('2024-12-01'),
    status: 'published',
  },
  {
    id: 'til-002',
    slug: 'angular-linked-signal',
    title: 'Angular linkedSignal 可以建立有預設值但可覆寫的 signal',
    content:
      '`linkedSignal` 讓你建立一個衍生 signal，它會跟隨來源自動更新，但使用者也可以手動設定值覆寫。下次來源改變時又會重新同步。很適合做「預設選項」的場景。',
    codeSnippet: `const items = signal(['Angular', 'React', 'Vue']);
const selectedItem = linkedSignal(() => items()[0]);

// selectedItem() === 'Angular'（自動跟隨）
selectedItem.set('React'); // 手動覆寫
// selectedItem() === 'React'

items.set(['Svelte', 'Solid', 'Qwik']);
// selectedItem() === 'Svelte'（來源改變，重新同步）`,
    codeLanguage: 'typescript',
    tags: ['Angular', 'TypeScript'],
    publishedAt: new Date('2024-11-29'),
    status: 'published',
  },
  {
    id: 'til-003',
    slug: 'rust-question-mark-operator',
    title: 'Rust ? 運算子可以在 main 函式中使用',
    content:
      '以前以為 `?` 只能在回傳 `Result` 的函式中使用。但 `main` 也可以回傳 `Result`，這樣就不需要一堆 `.unwrap()`。',
    codeSnippet: `fn main() -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string("config.toml")?;
    let config: Config = toml::from_str(&content)?;
    println!("Loaded: {:?}", config);
    Ok(())
}`,
    codeLanguage: 'rust',
    tags: ['Rust'],
    publishedAt: new Date('2024-11-27'),
    status: 'published',
  },
  {
    id: 'til-004',
    slug: 'tailwind-v4-shadow-xs',
    title: 'Tailwind v4 把 shadow-sm 改名為 shadow-xs',
    content:
      '升級到 Tailwind CSS v4 後所有 `shadow-sm` 都要改成 `shadow-xs`，`rounded-sm` 改成 `rounded-xs`。一開始沒注意到，花了不少時間除錯。',
    codeSnippet: `<!-- v3 -->
<div class="shadow-sm rounded-sm">...</div>

<!-- v4 -->
<div class="shadow-xs rounded-xs">...</div>`,
    codeLanguage: 'html',
    tags: ['Web Development'],
    publishedAt: new Date('2024-11-25'),
    status: 'published',
  },
  {
    id: 'til-005',
    slug: 'psql-explain-analyze',
    title: 'PostgreSQL EXPLAIN (ANALYZE, BUFFERS) 比 EXPLAIN 有用太多',
    content:
      '單獨用 `EXPLAIN` 只會給你查詢計畫的預估。加上 `ANALYZE` 會實際執行查詢並給你真實時間，加上 `BUFFERS` 會顯示 cache hit/miss。除錯慢查詢必備。',
    codeSnippet: `EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT u.name, COUNT(o.id)
FROM users u
JOIN orders o ON o.user_id = u.id
WHERE o.created_at > '2024-01-01'
GROUP BY u.name;`,
    codeLanguage: 'sql',
    tags: ['PostgreSQL'],
    publishedAt: new Date('2024-11-22'),
    status: 'published',
  },
  {
    id: 'til-006',
    slug: 'flutter-const-constructor',
    title: 'Flutter const constructor 可以大幅減少 widget rebuild',
    content:
      '如果一個 widget 的所有參數都是 compile-time constant，加上 `const` 關鍵字可以讓 Flutter 完全跳過 rebuild。在列表中特別有效。',
    codeSnippet: `// 每次 parent rebuild 都會重建
child: Padding(
  padding: EdgeInsets.all(16),
  child: Text('Hello'),
)

// 加上 const，Flutter 會重用同一個 instance
child: const Padding(
  padding: EdgeInsets.all(16),
  child: Text('Hello'),
)`,
    codeLanguage: 'dart',
    tags: ['Flutter'],
    publishedAt: new Date('2024-11-19'),
    status: 'published',
  },
];
