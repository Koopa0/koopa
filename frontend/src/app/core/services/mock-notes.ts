import { Note } from '../models/note.model';

export const MOCK_NOTES: Note[] = [
  {
    id: 'note-001',
    slug: 'go-dockerfile-multistage',
    title: 'Go Multi-stage Dockerfile 範本',
    content: `每次建新 Go 專案都會用到的 Dockerfile 範本。Multi-stage build 讓最終 image 只有幾 MB。

\`\`\`dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /app/server ./cmd/server

FROM alpine:3.20
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/server /server
EXPOSE 8080
CMD ["/server"]
\`\`\`

關鍵點：
- \`CGO_ENABLED=0\` 確保靜態連結
- \`-ldflags="-s -w"\` 減少 binary 大小
- 用 \`alpine\` 作為 base 而非 \`scratch\`，因為需要 CA 憑證`,
    category: 'snippet',
    tags: ['Golang'],
    publishedAt: new Date('2024-11-28'),
    updatedAt: new Date('2024-11-28'),
    status: 'published',
  },
  {
    id: 'note-002',
    slug: 'neovim-lsp-config',
    title: 'Neovim LSP 設定筆記',
    content: `常用的 LSP server 設定。使用 \`mason.nvim\` + \`nvim-lspconfig\`。

\`\`\`lua
require('mason-lspconfig').setup({
  ensure_installed = {
    'gopls', 'rust_analyzer', 'ts_ls',
    'angularls', 'tailwindcss', 'lua_ls',
  },
})
\`\`\`

Angular Language Service 需要在專案根目錄有 \`tsconfig.json\` 才能正確啟動。`,
    category: 'config',
    tags: ['Golang', 'Rust', 'TypeScript'],
    publishedAt: new Date('2024-11-24'),
    updatedAt: new Date('2024-11-24'),
    status: 'published',
  },
  {
    id: 'note-003',
    slug: 'designing-data-intensive-apps-ch1',
    title: '讀書筆記：Designing Data-Intensive Applications — Ch.1',
    content: `Martin Kleppmann 的經典。第一章定義了三個關鍵概念：

**Reliability（可靠性）**
- 系統在面對故障時仍能正確運作
- 硬體故障、軟體 bug、人為錯誤
- 容錯 (fault-tolerant) 不等於容災 (fault-preventing)

**Scalability（可擴展性）**
- 描述系統處理增長負載的能力
- 用 percentile（p50, p95, p99）描述效能，而非平均值
- Tail latency（p99.9）對大規模系統很重要

**Maintainability（可維護性）**
- Operability：讓運維容易
- Simplicity：管理複雜度（抽象是關鍵工具）
- Evolvability：讓變更容易

核心觀點：大多數應用程式是「資料密集型」而非「計算密集型」。瓶頸通常在資料的量、複雜度和變化速度。`,
    category: 'reading',
    tags: ['PostgreSQL'],
    publishedAt: new Date('2024-11-20'),
    updatedAt: new Date('2024-11-20'),
    status: 'published',
  },
  {
    id: 'note-004',
    slug: 'git-useful-aliases',
    title: '常用 Git Alias 設定',
    content: `放在 \`~/.gitconfig\` 的常用 alias：

\`\`\`ini
[alias]
  co = checkout
  br = branch
  ci = commit
  st = status -sb
  lg = log --oneline --graph --decorate -20
  undo = reset --soft HEAD~1
  amend = commit --amend --no-edit
  wip = !git add -A && git commit -m "wip"
  cleanup = !git branch --merged | grep -v '\\*\\|main\\|master' | xargs git branch -d
\`\`\`

\`git lg\` 是最常用的，一目瞭然的 commit graph。`,
    category: 'snippet',
    tags: ['Web Development'],
    publishedAt: new Date('2024-11-16'),
    updatedAt: new Date('2024-11-16'),
    status: 'published',
  },
  {
    id: 'note-005',
    slug: 'angular-testing-signal-pattern',
    title: 'Angular Signal 測試模式備忘',
    content: `測試 Signal 時的常見模式：

\`\`\`typescript
it('should update computed when source changes', () => {
  const source = signal(0);
  const doubled = computed(() => source() * 2);

  expect(doubled()).toBe(0);

  source.set(5);
  expect(doubled()).toBe(10);
});
\`\`\`

在 Component 測試中需要觸發 change detection：

\`\`\`typescript
fixture.componentRef.setInput('name', 'test');
fixture.detectChanges();
expect(compiled.textContent).toContain('test');
\`\`\``,
    category: 'snippet',
    tags: ['Angular', 'TypeScript'],
    publishedAt: new Date('2024-11-12'),
    updatedAt: new Date('2024-11-12'),
    status: 'published',
  },
];
