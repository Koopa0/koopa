/** Feed and feed-entry models. */

export type FeedEntryStatus = 'unread' | 'read' | 'curated' | 'ignored';

export type FeedPriority = 'high' | 'normal' | 'low';

export interface FeedRow {
  id: string;
  name: string;
  url: string;
  schedule: string;
  topic_slugs: string[];
  enabled: boolean;
  consecutive_failures: number;
  last_fetched_at: string | null;
  last_error: string | null;
  priority: FeedPriority;
}

export interface FeedEntryRow {
  id: string;
  title: string;
  excerpt: string;
  source_url: string;
  feed: { id: string; name: string };
  topic_slugs: string[];
  relevance_score: number | null;
  status: FeedEntryStatus;
  collected_at: string;
  published_at: string | null;
  curated_content_id: string | null;
  user_feedback: 'up' | 'down' | null;
}

export type FeedEntryFeedback = 'up' | 'down';
