-- Seed data — separated from schema definition for clarity.

-- ============================================================
-- Areas (PARA Areas of Responsibility)
-- ============================================================

-- The six real life-domains (PARA Areas). Names are authoritative; slugs are
-- ASCII romanizations for URL-safe addressing; descriptions are left blank for
-- the owner to fill in admin rather than seeded with assumed framing.
INSERT INTO areas (slug, name, description, sort_order) VALUES
    ('studio',     '工作室與系統', '', 1),
    ('japanese',   '日語',         '', 2),
    ('literature', '文學閱讀',     '', 3),
    ('yorushika',  'ヨルシカ',     '', 4),
    ('career',     '職涯',         '', 5),
    ('body',       '身體',         '', 6)
ON CONFLICT (slug) DO NOTHING;

-- ============================================================
-- Topics
-- ============================================================

-- Eight domains, not tags — each is an ongoing area of attention ("what I'm
-- working through"), the organizing axis of the public writing index. Kept
-- deliberately few so the home reads as a publication, not a tag cloud.
INSERT INTO topics (slug, name, description, sort_order) VALUES
    ('go',             'Go',             'Stdlib-first, no frameworks. Concurrency you can reason about.',                1),
    ('rust',           'Rust',           'Ownership, zero-cost abstractions, and what the borrow checker buys.',          2),
    ('system-design',  'System design',  'Tradeoffs under real constraints — storage, indexes, replication, the cost of convenience.', 3),
    ('infrastructure', 'Infrastructure', 'Containers, orchestration, networking — running a system and knowing what it is doing.', 4),
    ('ai-agents',      'AI & agents',    'LLMs, retrieval, and agents that share one semantic runtime with a human in the loop.', 5),
    ('frontend',       'Frontend',       'Angular, signals, and client craft where the interface gets out of the way.',   6),
    ('security',       'Security',       'Input boundaries, authz, and the failure modes you only see when you look for them.', 7),
    ('craft',          'Learning & craft','Reading above my level on purpose, problem-solving patterns, and working in the open.', 8),
    ('literature',     'Literature',     'Books, essays, and lyrics read as text worth close attention — ヨルシカ, and what stays with me.', 9)
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
            ('Ardan Labs',              ARRAY['go','rust','infrastructure']),
            ('The Go Blog',             ARRAY['go']),
            ('Golang Weekly',           ARRAY['go']),
            ('Alex Edwards',            ARRAY['go']),
            ('Rust Blog',               ARRAY['rust']),
            ('This Week in Rust',       ARRAY['rust']),
            ('Angular Blog',            ARRAY['frontend']),
            ('Flutter Blog',            ARRAY['frontend']),
            ('Cloudflare Blog',         ARRAY['infrastructure','security']),
            ('Simon Willison''s Weblog', ARRAY['ai-agents']),
            ('Google Research Blog',    ARRAY['ai-agents']),
            ('Latent Space',            ARRAY['ai-agents']),
            ('Google AI Blog',          ARRAY['ai-agents']),
            ('DeepMind Blog',           ARRAY['ai-agents']),
            ('Google Developers Blog',  ARRAY['go','frontend','ai-agents']),
            ('Google Cloud Blog',       ARRAY['infrastructure','ai-agents']),
            ('Google Dev Updates',      ARRAY['go','frontend','ai-agents']),
            ('Hugging Face Blog',       ARRAY['ai-agents']),
            ('ByteByteGo',             ARRAY['system-design']),
            ('Anthropic Blog',          ARRAY['ai-agents'])
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
-- Agent schedules
-- ============================================================
-- Schedule definitions live in the Go BuiltinAgents() literal under
-- internal/agent/registry.go, not in the database. Only the run audit log
-- (process_runs, kind='agent_schedule', subsystem=agent.Platform) persists here.
