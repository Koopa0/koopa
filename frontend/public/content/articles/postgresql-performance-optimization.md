# PostgreSQL 效能優化：索引策略與查詢調優

## 效能優化概述

PostgreSQL 效能優化是一個系統性的工程，涉及索引設計、查詢優化、配置調優等多個方面。

## 索引策略

### 基本索引類型

```sql
-- B-tree 索引 (預設)
CREATE INDEX idx_users_email ON users(email);

-- 複合索引
CREATE INDEX idx_orders_user_date ON orders(user_id, created_at);

-- 部分索引
CREATE INDEX idx_active_users ON users(email) WHERE status = 'active';

-- 表達式索引
CREATE INDEX idx_users_lower_email ON users(LOWER(email));
```

### 特殊索引類型

```sql
-- GIN 索引 (適用於陣列、JSON)
CREATE INDEX idx_tags_gin ON articles USING GIN(tags);

-- GiST 索引 (適用於幾何資料)
CREATE INDEX idx_location_gist ON stores USING GIST(location);

-- Hash 索引 (適用於等值查詢)
CREATE INDEX idx_users_hash ON users USING HASH(user_id);
```

## 查詢分析與優化

### 使用 EXPLAIN

```sql
-- 查看查詢計劃
EXPLAIN SELECT * FROM users WHERE email = 'user@example.com';

-- 查看實際執行統計
EXPLAIN (ANALYZE, BUFFERS)
SELECT u.name, COUNT(o.id)
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;
```

### 查詢優化技巧

```sql
-- 避免 SELECT *
SELECT id, name, email FROM users WHERE status = 'active';

-- 使用 LIMIT 限制結果
SELECT * FROM articles ORDER BY created_at DESC LIMIT 10;

-- 適當使用 EXISTS 而非 IN
SELECT * FROM users u
WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.id);

-- 使用窗口函數
SELECT
  user_id,
  order_date,
  ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY order_date DESC) as rn
FROM orders;
```

## 配置優化

### 記憶體配置

```sql
-- postgresql.conf
shared_buffers = 256MB          -- 共享緩衝區
effective_cache_size = 1GB      -- 作業系統快取大小
work_mem = 4MB                  -- 排序和雜湊操作記憶體
maintenance_work_mem = 64MB     -- 維護操作記憶體
```

### 連線與寫入優化

```sql
max_connections = 100           -- 最大連線數
checkpoint_timeout = 10min      -- 檢查點間隔
checkpoint_completion_target = 0.9
wal_buffers = 16MB             -- WAL 緩衝區
```

## 監控與維護

### 查詢統計

```sql
-- 啟用查詢統計
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- 查看最慢的查詢
SELECT
  query,
  calls,
  total_time,
  total_time/calls as avg_time,
  rows
FROM pg_stat_statements
ORDER BY total_time DESC
LIMIT 10;
```

### 索引使用統計

```sql
-- 檢查索引使用情況
SELECT
  schemaname,
  tablename,
  indexname,
  idx_tup_read,
  idx_tup_fetch
FROM pg_stat_user_indexes
ORDER BY idx_tup_read DESC;

-- 找出未使用的索引
SELECT
  schemaname,
  tablename,
  indexname
FROM pg_stat_user_indexes
WHERE idx_tup_read = 0
  AND idx_tup_fetch = 0;
```

### 表維護

```sql
-- 分析表統計資訊
ANALYZE users;

-- 重建索引
REINDEX INDEX idx_users_email;

-- 清理死元組
VACUUM ANALYZE users;
```

## 進階優化技巧

### 分割表

```sql
-- 建立分割表
CREATE TABLE orders (
  id SERIAL,
  user_id INTEGER,
  order_date DATE,
  amount DECIMAL
) PARTITION BY RANGE (order_date);

-- 建立子表
CREATE TABLE orders_2024_q1 PARTITION OF orders
FOR VALUES FROM ('2024-01-01') TO ('2024-04-01');
```

### 物化視圖

```sql
-- 建立物化視圖
CREATE MATERIALIZED VIEW user_order_summary AS
SELECT
  u.id,
  u.name,
  COUNT(o.id) as order_count,
  SUM(o.amount) as total_amount
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.name;

-- 建立索引
CREATE INDEX idx_user_order_summary_id ON user_order_summary(id);

-- 重新整理物化視圖
REFRESH MATERIALIZED VIEW user_order_summary;
```

## 效能測試

### pgbench 壓力測試

```bash
# 初始化測試資料
pgbench -i -s 10 testdb

# 執行壓力測試
pgbench -c 10 -j 2 -t 1000 testdb
```

## 最佳實踐

1. **定期分析表統計資訊**
2. **監控慢查詢日誌**
3. **合理設計索引策略**
4. **適當使用連線池**
5. **定期維護資料庫**

## 總結

PostgreSQL 效能優化是一個持續的過程。通過合理的索引設計、查詢優化和配置調優，可以顯著提升資料庫效能。
