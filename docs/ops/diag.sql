-- ============================================================
-- koopa0.dev 診斷包 v1（全部 read-only）— 2026-07-05
-- 用法: psql "$DATABASE_URL" -f diag.sql -o diag_out.txt
-- 跑完把 diag_out.txt 貼回對話。本檔為暫存,可刪。
-- ============================================================

-- ── Q1. Todo 積壓真相:state × 來源矩陣
SELECT '=== Q1a todos: state x created_by ===' AS section;
SELECT state, COALESCE(created_by,'(null)') AS created_by, count(*)
FROM todos GROUP BY 1,2 ORDER BY 1,2;

SELECT '=== Q1b inbox 積壓明細(最老 50 筆)===' AS section;
SELECT left(title,60) AS title, created_by, created_at::date,
       (now()::date - created_at::date) AS age_days
FROM todos WHERE state='inbox' ORDER BY created_at LIMIT 50;

-- ── Q2. Todo 流量:每週開單 vs 結單
SELECT '=== Q2 todos: weekly opened vs completed ===' AS section;
SELECT wk, sum(opened) AS opened, sum(completed) AS completed FROM (
  SELECT date_trunc('week',created_at)::date AS wk, count(*) AS opened, 0 AS completed
    FROM todos GROUP BY 1
  UNION ALL
  SELECT date_trunc('week',completed_at)::date, 0, count(*)
    FROM todos WHERE completed_at IS NOT NULL GROUP BY 1
) t GROUP BY wk ORDER BY wk;

-- ── Q3. Content 全貌 + embedding 覆蓋
SELECT '=== Q3a contents: type x status x is_public x created_by ===' AS section;
SELECT type, status, is_public, COALESCE(created_by,'(null)') AS created_by, count(*)
FROM contents GROUP BY 1,2,3,4 ORDER BY 1,2,3;

SELECT '=== Q3b embedding coverage ===' AS section;
SELECT count(*) AS total_non_archived,
       count(*) FILTER (WHERE embedding IS NULL) AS missing_embedding
FROM contents WHERE status <> 'archived';

-- ── Q4. RSS/curation 漏斗
SELECT '=== Q4a feeds health ===' AS section;
SELECT name, enabled, priority, schedule, last_fetched_at::date AS last_fetch,
       consecutive_failures, (last_error IS NOT NULL) AS has_err
FROM feeds ORDER BY enabled DESC, priority, name;

SELECT '=== Q4b feed_entries funnel ===' AS section;
SELECT status, count(*), min(collected_at)::date AS oldest, max(collected_at)::date AS newest
FROM feed_entries GROUP BY 1;

-- ── Q5. Activity:每月每 actor 事件量 + owner 活躍天數
SELECT '=== Q5a activity per actor per month ===' AS section;
SELECT date_trunc('month',occurred_at)::date AS mo, actor, count(*)
FROM activity_events GROUP BY 1,2 ORDER BY 1,2;

SELECT '=== Q5b human active days (all time) ===' AS section;
SELECT count(DISTINCT occurred_at::date) AS human_active_days,
       min(occurred_at)::date AS first, max(occurred_at)::date AS last
FROM activity_events WHERE actor='human';

SELECT '=== Q5c event mix ===' AS section;
SELECT entity_type, change_kind, count(*) FROM activity_events
GROUP BY 1,2 ORDER BY 3 DESC;

-- ── Q6. plan_day 實際使用
SELECT '=== Q6a daily_plan_items by selector ===' AS section;
SELECT selected_by, count(*) AS items, count(DISTINCT plan_date) AS days_planned
FROM daily_plan_items GROUP BY 1;

SELECT '=== Q6b plan item outcomes ===' AS section;
SELECT status, count(*) FROM daily_plan_items GROUP BY 1;

SELECT '=== Q6c 最近 14 個 plan 日 ===' AS section;
SELECT plan_date, count(*) AS items,
       count(*) FILTER (WHERE status='done') AS done
FROM daily_plan_items GROUP BY 1 ORDER BY 1 DESC LIMIT 14;

-- ── Q7. propose_* 歷史:存活提案 + 硬刪(=reject)量
SELECT '=== Q7a surviving agent-created PARA rows ===' AS section;
SELECT 'area' AS kind, status::text, created_by, count(*) FROM areas
  WHERE created_by IS NOT NULL GROUP BY 2,3
UNION ALL
SELECT 'goal', status::text, created_by, count(*) FROM goals
  WHERE created_by IS NOT NULL GROUP BY 2,3
UNION ALL
SELECT 'project', status::text, created_by, count(*) FROM projects
  WHERE created_by IS NOT NULL GROUP BY 2,3
ORDER BY 1,2;

SELECT '=== Q7b created-then-hard-deleted per entity ===' AS section;
SELECT ae.entity_type, ae.actor, count(DISTINCT ae.entity_id) AS created_then_deleted
FROM activity_events ae
WHERE ae.change_kind='created'
  AND CASE ae.entity_type
    WHEN 'todo'      THEN NOT EXISTS (SELECT 1 FROM todos t WHERE t.id=ae.entity_id)
    WHEN 'goal'      THEN NOT EXISTS (SELECT 1 FROM goals g WHERE g.id=ae.entity_id)
    WHEN 'milestone' THEN NOT EXISTS (SELECT 1 FROM milestones m WHERE m.id=ae.entity_id)
    WHEN 'project'   THEN NOT EXISTS (SELECT 1 FROM projects p WHERE p.id=ae.entity_id)
    WHEN 'content'   THEN NOT EXISTS (SELECT 1 FROM contents c WHERE c.id=ae.entity_id)
  END
GROUP BY 1,2 ORDER BY 3 DESC;

-- ── Q8. Milestones:總量 + 完成時間分佈
SELECT '=== Q8 milestones completion clustering ===' AS section;
SELECT count(*) AS total, count(completed_at) AS done FROM milestones;
SELECT completed_at::date AS day, count(*) FROM milestones
WHERE completed_at IS NOT NULL GROUP BY 1 ORDER BY 1;

-- ── Q9. Recurring todos + occurrence 事件軌跡
SELECT '=== Q9a recurring todos ===' AS section;
SELECT left(title,50) AS title, state, recur_interval, recur_unit, recur_weekdays,
       last_completed_on::date AS last_done, created_by
FROM todos WHERE recur_interval IS NOT NULL OR recur_weekdays IS NOT NULL;

SELECT '=== Q9b recurring todo event trail ===' AS section;
SELECT left(t.title,40) AS title, ae.change_kind, count(*),
       max(ae.occurred_at)::date AS last_event
FROM activity_events ae JOIN todos t ON t.id=ae.entity_id
WHERE t.recur_interval IS NOT NULL OR t.recur_weekdays IS NOT NULL
GROUP BY 1,2 ORDER BY 1,2;

-- ── Q10. DB 大小(備份策略輸入)
SELECT '=== Q10 db + table sizes ===' AS section;
SELECT pg_size_pretty(pg_database_size(current_database())) AS db_size;
SELECT c.relname, pg_size_pretty(pg_total_relation_size(c.oid)) AS size
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relkind='r'
ORDER BY pg_total_relation_size(c.oid) DESC LIMIT 15;

-- ── Q11. process_runs:collector 健康度
SELECT '=== Q11 process_runs health ===' AS section;
SELECT status, count(*), max(created_at)::date AS latest FROM process_runs GROUP BY 1;
SELECT name, count(*) FILTER (WHERE status='failed') AS failed, count(*) AS total,
       max(ended_at)::date AS last_run
FROM process_runs GROUP BY 1 ORDER BY failed DESC, total DESC LIMIT 15;

-- ── Q12. 中文 FTS 真相探針
SELECT '=== Q12a CJK tokenization probe ===' AS section;
SELECT to_tsvector('simple', 'Go 工程師的成本意識：每一行程式碼都是未來的帳單') AS cjk_tokens;

SELECT '=== Q12b 中文詞查詢是否命中 ===' AS section;
SELECT count(*) AS hits_for_cost_term
FROM contents WHERE search_vector @@ websearch_to_tsquery('simple','成本');
SELECT count(*) AS hits_for_full_phrase
FROM contents WHERE search_vector @@ websearch_to_tsquery('simple','每一行程式碼都是未來的帳單');
