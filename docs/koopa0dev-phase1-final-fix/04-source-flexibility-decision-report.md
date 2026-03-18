# koopa0.dev Source Flexibility Redesign — 技術決策報告

> **Status**: 決策完成（Reference — 需要更深 trade-off context 時查閱）
> **Date**: 2026-03-16
> **Context**: 基於 Opus 提案與 v3.0 設計文件的交叉審查

---

## 一、提案 A：Notion Source Registry

### 採納的設計

建立 `notion_sources` 配置表，用宣告式方式描述每個 Notion database 的 sync 行為。

sync_mode 只需要 `full` 和 `events` 兩個（不需要 `snapshot`）。

**property_map 完整結構**（含 type 和 extract 欄位）：

```json
{
  "Status": {
    "canonical": "status",
    "type": "select",
    "extract": "name"
  },
  "Due Date": {
    "canonical": "deadline",
    "type": "date",
    "extract": "start"
  },
  "Related Project": {
    "canonical": "project",
    "type": "relation",
    "extract": "title"
  }
}
```

`type` 欄位的必要性：Schema drift detection（config 說 select，API 回 multi_select → alert）。Admin UI 配置校驗（checkbox 映射成 deadline → type mismatch）。

**Generic sync Go pseudo-code：**

```go
func extractValue(prop notion.Property, mapping PropertyMapping) (string, error) {
    if prop.Type != mapping.Type {
        alertSchemaDrift(mapping.Canonical, mapping.Type, prop.Type)
    }
    switch mapping.Type {
    case "select":
        if prop.Select == nil { return "", nil }
        return getField(prop.Select, mapping.Extract), nil
    case "multi_select":
        names := make([]string, len(prop.MultiSelect))
        for i, s := range prop.MultiSelect {
            names[i] = getField(s, mapping.Extract)
        }
        return strings.Join(names, ", "), nil
    case "date":
        if prop.Date == nil { return "", nil }
        return getField(prop.Date, mapping.Extract), nil
    case "relation":
        ids := make([]string, len(prop.Relation))
        for i, r := range prop.Relation { ids[i] = r.ID }
        return strings.Join(ids, ","), nil
    case "rich_text":
        if len(prop.RichText) == 0 { return "", nil }
        return prop.RichText[0].PlainText, nil
    default:
        return fmt.Sprintf("%v", prop), nil
    }
}
```

### 遷移策略

Phase 1.5 建 table + Admin UI。先 onboard events mode 新 databases。四個 full mode databases 在 table 裡建記錄但 sync 不動。Phase 2 才遷移 sync code 讀取來源。

---

## 二、提案 B：Obsidian 兩層 Ingestion

### 決策：先觀察再決定

Phase 1 埋 Prometheus counter（`obsidian_notes_missing_frontmatter_total`），跑一個月看數據。超過 10% 建 `obsidian_raw` table 做 Tier 2。否則不投資。

`IsComplete()` 只檢查 `type` field。

---

## 三、提案 C：Tag Normalization

### 採納的設計

兩張 table（`tags` + `tag_aliases`），帶 parent-child 層級。Ingestion-time normalization 優於 query-time。四步 pipeline（exact → case-insensitive → slug → unknown）。

Auto-mapping 分 match_method 區別：case-insensitive auto-confirm，fuzzy pending，unknown unmapped。

不做 Obsidian 端 tag Linter。

---

## 四、提案 D：tsvector Configuration

### 採納的設計

從 `english` 換成 `simple`。不做 dual configuration。CamelCase preprocessing 放 Go 層，新增 `search_text` column。

---

## 五、管理介面架構

Admin UI 是唯一管理介面，不建 CLI。Domain service → HTTP handler → Angular admin module。

---

## 六、綜合優先級

### Phase 1

tsvector migration → tags + tag_aliases → activity_events → Obsidian frontmatter → Genkit flow pilot → Admin UI tag 管理。

### Phase 1.5

notion_sources table + Admin UI → events-only sync → Obsidian Tier 2 決策。

### 不做

CLI、dual tsvector、snapshot mode、Linter、description drift detection、Cross-Project Transfer（Phase 4）、CRM（推遲）。
