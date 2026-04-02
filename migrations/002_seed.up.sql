-- Seed data — separated from schema definition for clarity.

-- ============================================================
-- Topics
-- ============================================================

INSERT INTO topics (slug, name, sort_order) VALUES
    ('go',             'Go',              1),
    ('rust',           'Rust',            2),
    ('angular',        'Angular',         3),
    ('flutter',        'Flutter',         4),
    ('dart',           'Dart',            5),
    ('frontend',       'Frontend',        6),
    ('mobile',         'Mobile',          7),
    ('ai',             'AI',              8),
    ('llm',            'LLM',             9),
    ('ml',             'Machine Learning', 10),
    ('claude',         'Claude',          11),
    ('kubernetes',     'Kubernetes',      12),
    ('docker',         'Docker',          13),
    ('infra',          'Infrastructure',  14),
    ('networking',     'Networking',      15),
    ('workers',        'Workers',         16),
    ('devops',         'DevOps',          17),
    ('system-design',  'System Design',   18),
    ('database',       'Database',        19),
    ('security',       'Security',        20),
    ('performance',    'Performance',     21),
    ('design',         'Design',          22),
    ('career',         'Career',          23),
    ('open-source',    'Open Source',     24)
ON CONFLICT (slug) DO NOTHING;

-- ============================================================
-- Tags (canonical LeetCode/HackerRank vocabulary)
-- ============================================================

INSERT INTO tags (slug, name) VALUES
    ('array', 'Array'), ('string', 'String'), ('hash-table', 'Hash Table'),
    ('two-pointers', 'Two Pointers'), ('sliding-window', 'Sliding Window'),
    ('binary-search', 'Binary Search'), ('stack', 'Stack'), ('queue', 'Queue'),
    ('monotonic-stack', 'Monotonic Stack'), ('linked-list', 'Linked List'),
    ('tree', 'Tree'), ('binary-tree', 'Binary Tree'), ('bst', 'BST'),
    ('graph', 'Graph'), ('bfs', 'BFS'), ('dfs', 'DFS'),
    ('heap', 'Heap'), ('trie', 'Trie'), ('union-find', 'Union Find'),
    ('dp', 'Dynamic Programming'), ('greedy', 'Greedy'), ('backtracking', 'Backtracking'),
    ('bit-manipulation', 'Bit Manipulation'), ('math', 'Math'), ('matrix', 'Matrix'),
    ('interval', 'Interval'), ('topological-sort', 'Topological Sort'),
    ('sorting', 'Sorting'), ('simulation', 'Simulation'), ('prefix-sum', 'Prefix Sum'),
    ('divide-and-conquer', 'Divide and Conquer'), ('segment-tree', 'Segment Tree'),
    ('binary-indexed-tree', 'Binary Indexed Tree'),
    ('design', 'Design'),
    ('easy', 'Easy'), ('medium', 'Medium'), ('hard', 'Hard'),
    ('ac-independent', 'AC Independent'), ('ac-with-hints', 'AC With Hints'),
    ('ac-after-solution', 'AC After Solution'), ('incomplete', 'Incomplete'),
    ('weakness:pattern-recognition', 'Weakness: Pattern Recognition'),
    ('weakness:approach-selection', 'Weakness: Approach Selection'),
    ('weakness:state-transition', 'Weakness: State Transition'),
    ('weakness:edge-cases', 'Weakness: Edge Cases'),
    ('weakness:complexity-analysis', 'Weakness: Complexity Analysis'),
    ('weakness:implementation', 'Weakness: Implementation'),
    ('weakness:time-management', 'Weakness: Time Management'),
    ('weakness:constraint-analysis', 'Weakness: Constraint Analysis'),
    ('weakness:loop-condition', 'Weakness: Loop Condition'),
    ('improvement:pattern-recognition', 'Improvement: Pattern Recognition'),
    ('improvement:approach-selection', 'Improvement: Approach Selection'),
    ('improvement:state-transition', 'Improvement: State Transition'),
    ('improvement:edge-cases', 'Improvement: Edge Cases'),
    ('improvement:complexity-analysis', 'Improvement: Complexity Analysis'),
    ('improvement:constraint-analysis', 'Improvement: Constraint Analysis'),
    ('improvement:implementation', 'Improvement: Implementation'),
    ('improvement:loop-condition', 'Improvement: Loop Condition'),
    ('leetcode', 'LeetCode'), ('hackerrank', 'HackerRank')
ON CONFLICT (slug) DO NOTHING;

-- ============================================================
-- Feeds (with correct priority inline, no UPDATE needed)
-- ============================================================

-- Helper: resolve topic slugs to UUIDs for feed_topics junction.
-- We INSERT feeds first, then populate feed_topics using a CTE.

INSERT INTO feeds (url, name, schedule, priority, filter_config) VALUES
    ('https://www.ardanlabs.com/index.xml', 'Ardan Labs', 'daily', 'high',
     '{"deny_paths":["/news","/events","/team-live-training-courses","/self-paced-courses","/training","/self-paced-teams","/self-paced-individuals"]}'),
    ('https://go.dev/blog/feed.atom', 'The Go Blog', 'daily', 'high', '{}'),
    ('https://golangweekly.com/rss/', 'Golang Weekly', 'weekly', 'normal',
     '{"deny_title_patterns":["(?i)sponsored"]}'),
    ('https://www.alexedwards.net/static/feed.rss', 'Alex Edwards', 'daily', 'normal', '{}'),
    ('https://blog.rust-lang.org/feed.xml', 'Rust Blog', 'daily', 'high', '{}'),
    ('https://this-week-in-rust.org/atom.xml', 'This Week in Rust', 'weekly', 'normal', '{}'),
    ('https://blog.angular.dev/feed', 'Angular Blog', 'daily', 'normal', '{}'),
    ('https://blog.flutter.dev/feed', 'Flutter Blog', 'daily', 'normal', '{}'),
    ('https://blog.cloudflare.com/rss/', 'Cloudflare Blog', 'daily', 'normal',
     '{"deny_title_patterns":["(?i)birthday week","(?i)speed week","(?i)developer week","(?i)security week","(?i)innovation week","(?i)impact week","(?i)welcome to .* week","(?i)new pricing","(?i)announcing .* plan"],"deny_tags":["product-news","partners","case-study","legal"]}'),
    ('https://simonwillison.net/atom/everything/', 'Simon Willison''s Weblog', 'daily', 'high', '{}'),
    ('https://research.google/blog/rss/', 'Google Research Blog', 'daily', 'normal',
     '{"deny_title_patterns":["(?i)health","(?i)medical","(?i)quantum","(?i)biology","(?i)climate","(?i)flood","(?i)wildfire"]}'),
    ('https://www.latent.space/feed', 'Latent Space', 'weekly', 'normal', '{}'),
    ('https://blog.google/technology/ai/rss/', 'Google AI Blog', 'daily', 'high',
     '{"deny_title_patterns":["(?i)health","(?i)medical","(?i)quantum"]}'),
    ('https://deepmind.google/blog/rss.xml', 'DeepMind Blog', 'weekly', 'normal',
     '{"deny_title_patterns":["(?i)health","(?i)medical","(?i)quantum","(?i)biology","(?i)climate"]}'),
    ('https://developers.googleblog.com/feeds/posts/default', 'Google Developers Blog', 'daily', 'high',
     '{"deny_title_patterns":["(?i)devfest","(?i)women techmakers","(?i)student"]}'),
    ('https://cloud.google.com/blog/rss', 'Google Cloud Blog', 'daily', 'normal',
     '{"deny_title_patterns":["(?i)customer story","(?i)case study","(?i)partner","(?i)pricing","(?i)event recap"]}'),
    ('https://blog.google/technology/developers/rss/', 'Google Dev Updates', 'weekly', 'normal', '{}'),
    ('https://huggingface.co/blog/feed.xml', 'Hugging Face Blog', 'daily', 'normal',
     '{"deny_title_patterns":["(?i)community update","(?i)partnership"],"deny_tags":["community","partnerships"]}'),
    ('https://blog.bytebytego.com/feed', 'ByteByteGo', 'weekly', 'normal',
     '{"deny_title_patterns":["(?i)black friday","(?i)discount","(?i)course launch"]}'),
    ('https://www.anthropic.com/rss.xml', 'Anthropic Blog', 'daily', 'high', '{}')
ON CONFLICT (url) DO NOTHING;

-- ============================================================
-- Feed ↔ Topic associations (replaces old TEXT[] column)
-- ============================================================

-- Using a DO block to resolve slugs → UUIDs without repeating subqueries.
DO $$
DECLARE
    _feed_id UUID;
    _topic_slug TEXT;
    _topic_id UUID;
    _mapping RECORD;
BEGIN
    -- Feed-topic mapping: (feed_name, topic_slugs[])
    FOR _mapping IN
        SELECT * FROM (VALUES
            ('Ardan Labs',              ARRAY['go','rust','kubernetes','ai','devops','design']),
            ('The Go Blog',             ARRAY['go']),
            ('Golang Weekly',           ARRAY['go']),
            ('Alex Edwards',            ARRAY['go']),
            ('Rust Blog',               ARRAY['rust']),
            ('This Week in Rust',       ARRAY['rust']),
            ('Angular Blog',            ARRAY['angular','frontend']),
            ('Flutter Blog',            ARRAY['flutter','dart','mobile']),
            ('Cloudflare Blog',         ARRAY['infra','networking','workers']),
            ('Simon Willison''s Weblog', ARRAY['ai','llm']),
            ('Google Research Blog',    ARRAY['ai','ml']),
            ('Latent Space',            ARRAY['ai','llm']),
            ('Google AI Blog',          ARRAY['ai','llm','ml']),
            ('DeepMind Blog',           ARRAY['ai','ml']),
            ('Google Developers Blog',  ARRAY['go','angular','flutter','ai','mobile','frontend']),
            ('Google Cloud Blog',       ARRAY['kubernetes','docker','infra','database','ai']),
            ('Google Dev Updates',      ARRAY['go','angular','flutter','ai']),
            ('Hugging Face Blog',       ARRAY['ai','llm','ml']),
            ('ByteByteGo',             ARRAY['system-design']),
            ('Anthropic Blog',          ARRAY['ai','llm'])
        ) AS t(feed_name, topic_slugs)
    LOOP
        SELECT id INTO _feed_id FROM feeds WHERE name = _mapping.feed_name;
        IF _feed_id IS NULL THEN CONTINUE; END IF;

        FOREACH _topic_slug IN ARRAY _mapping.topic_slugs
        LOOP
            SELECT id INTO _topic_id FROM topics WHERE slug = _topic_slug;
            IF _topic_id IS NOT NULL THEN
                INSERT INTO feed_topics(feed_id, topic_id) VALUES (_feed_id, _topic_id)
                ON CONFLICT DO NOTHING;
            END IF;
        END LOOP;
    END LOOP;
END $$;

-- ============================================================
-- Participant schedules (known schedules from Cowork instructions)
-- ============================================================

INSERT INTO participant_schedules (participant, name, purpose, trigger_type, schedule_expr, execution_backend, instruction_template, expected_outputs, missed_run_policy) VALUES
    ('hq', 'Morning Briefing', 'Daily briefing: tasks, projects, goals, insights, RSS highlights',
     'cron', '0 8 * * *', 'cowork_desktop',
     'Execute morning briefing flow: morning_context → produce briefing → write directives for departments',
     '{"directive", "journal:plan"}', 'run_once_on_wake'),

    ('hq', 'Weekly Review', 'Weekly summary and next-week planning',
     'cron', '0 17 * * 5', 'cowork_desktop',
     'Execute weekly review: weekly_summary → review department reports → write reflection + new directives',
     '{"directive", "journal:reflection"}', 'run_once_on_wake'),

    ('content-studio', 'Pipeline Check', 'Daily content pipeline health + RSS monitoring',
     'cron', '0 14 * * *', 'cowork_desktop',
     'Read directives → list_content_queue → rss_highlights → write report',
     '{"report"}', 'skip'),

    ('research-lab', 'Industry Scan', 'Weekly industry trend scanning',
     'cron', '0 9 * * 1', 'cowork_desktop',
     'Read directives → RSS + web search → produce industry trend report',
     '{"report"}', 'skip');
