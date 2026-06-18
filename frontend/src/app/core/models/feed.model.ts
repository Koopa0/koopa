/** Feed and feed-entry models. */

export type FeedEntryStatus = 'unread' | 'read' | 'curated' | 'ignored';

export type FeedPriority = 'high' | 'normal' | 'low';

export interface FeedRow {
  id: string;
  name: string;
  url: string;
  schedule: string;
  topics: string[];
  enabled: boolean;
  priority: FeedPriority;
  consecutive_failures: number;
  last_fetched_at: string | null;
  last_error: string;
  /** Set to the failure cause after MaxConsecutiveFailures auto-disables a feed; empty otherwise. */
  disabled_reason: string;
  created_at: string;
}

export interface FeedEntryRow {
  id: string;
  source_url: string;
  feed_name: string;
  title: string;
  /** RSS entry content/summary as delivered by the feed. Absent when none. */
  original_content?: string;
  status: FeedEntryStatus;
  curated_content_id: string | null;
  collected_at: string;
  published_at: string | null;
  feed_id: string | null;
}
