/** Unified API response format — matches backend JSON structure */

export interface ApiResponse<T> {
  data: T;
}

export interface ApiListResponse<T> {
  data: T[];
  meta: ApiPaginationMeta;
}

export interface ApiPaginationMeta {
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

export interface ApiError {
  error: {
    code: string;
    message: string;
  };
}

/** Backend Content object (snake_case, matches API response) */
export interface ApiContent {
  id: string;
  slug: string;
  title: string;
  body: string;
  excerpt: string;
  type: ContentType;
  status: ContentStatus;
  tags: string[];
  topics: ApiTopic[];
  cover_image: string | null;
  source: string | null;
  source_type: string | null;
  series_id: string | null;
  series_order: number | null;
  review_level: ReviewLevel;
  ai_metadata: Record<string, unknown> | null;
  reading_time: number;
  published_at: string | null;
  created_at: string;
  updated_at: string;
}

export type ContentType =
  | 'article'
  | 'essay'
  | 'build-log'
  | 'til'
  | 'note'
  | 'bookmark'
  | 'digest';

export type ContentStatus = 'draft' | 'review' | 'published' | 'archived';

export type ReviewLevel = 'auto' | 'light' | 'standard' | 'strict';

/** Backend Topic object */
export interface ApiTopic {
  id: string;
  slug: string;
  name: string;
  description: string;
  icon: string;
  content_count: number;
  sort_order: number;
  created_at: string;
  updated_at: string;
}

/** Backend Project object */
export interface ApiProject {
  id: string;
  slug: string;
  title: string;
  description: string;
  long_description: string | null;
  role: string;
  tech_stack: string[];
  highlights: string[];
  problem: string | null;
  solution: string | null;
  architecture: string | null;
  results: string | null;
  github_url: string | null;
  live_url: string | null;
  featured: boolean;
  public: boolean;
  sort_order: number;
  status: ProjectStatus;
  created_at: string;
  updated_at: string;
}

export type ProjectStatus =
  | 'in-progress'
  | 'completed'
  | 'maintained'
  | 'archived';

/** Backend Auth response */
export interface ApiTokenResponse {
  access_token: string;
  refresh_token: string;
}

/** JWT payload (backend Claims struct — email allowlist, no role field) */
export interface JwtPayload {
  sub: string;
  email: string;
  exp: number;
  iat: number;
}

/** Admin — Create/Update Content request */
export interface ApiCreateContentRequest {
  slug: string;
  title: string;
  body?: string;
  excerpt?: string;
  type: ContentType;
  status?: ContentStatus;
  tags?: string[];
  topic_ids?: string[];
  cover_image?: string;
  source?: string;
  source_type?: string;
  series_id?: string;
  series_order?: number;
  review_level?: ReviewLevel;
  ai_metadata?: Record<string, unknown>;
  reading_time?: number;
}

export interface ApiUpdateContentRequest {
  slug?: string;
  title?: string;
  body?: string;
  excerpt?: string;
  tags?: string[];
  topic_ids?: string[];
  cover_image?: string;
  status?: ContentStatus;
  series_id?: string;
  series_order?: number;
  review_level?: ReviewLevel;
  ai_metadata?: Record<string, unknown>;
  reading_time?: number;
}

/** Admin — Create/Update Project request */
export interface ApiCreateProjectRequest {
  slug: string;
  title: string;
  description: string;
  long_description?: string;
  role: string;
  tech_stack?: string[];
  highlights?: string[];
  problem?: string;
  solution?: string;
  architecture?: string;
  results?: string;
  github_url?: string;
  live_url?: string;
  featured?: boolean;
  public?: boolean;
  sort_order?: number;
  status?: ProjectStatus;
}

export type ApiUpdateProjectRequest = Partial<ApiCreateProjectRequest>;

/** Admin — Create/Update Topic request */
export interface ApiCreateTopicRequest {
  slug: string;
  name: string;
  description?: string;
  icon?: string;
  sort_order?: number;
}

export type ApiUpdateTopicRequest = Partial<ApiCreateTopicRequest>;

/** Admin — Review */
export type ReviewStatus = 'pending' | 'approved' | 'rejected' | 'edited';

export interface ApiReviewItem {
  id: string;
  content_id: string;
  review_level: ReviewLevel;
  status: ReviewStatus;
  reviewer_notes: string | null;
  content_title: string;
  content_slug: string;
  content_type: ContentType;
  submitted_at: string;
  reviewed_at: string | null;
}

/** Admin — RSS Feed */
export interface FeedFilterConfig {
  deny_paths?: string[];
  deny_title_patterns?: string[];
  allow_tags?: string[];
  deny_tags?: string[];
}

export interface ApiFeed {
  id: string;
  url: string;
  name: string;
  schedule: FeedSchedule;
  topics: string[];
  enabled: boolean;
  etag: string;
  last_modified: string;
  last_fetched_at: string | null;
  consecutive_failures: number;
  last_error: string;
  disabled_reason: string;
  filter_config: FeedFilterConfig;
  created_at: string;
  updated_at: string;
}

export type FeedSchedule = 'hourly_4' | 'daily' | 'weekly';

export interface ApiCreateFeedRequest {
  url: string;
  name: string;
  schedule: FeedSchedule;
  topics?: string[];
  filter_config?: FeedFilterConfig;
}

export interface ApiUpdateFeedRequest {
  url?: string;
  name?: string;
  schedule?: string;
  topics?: string[];
  enabled?: boolean;
  filter_config?: FeedFilterConfig;
}

/** Admin — Collected items */
export type CollectedStatus = 'unread' | 'read' | 'curated' | 'ignored';
export type CollectedFeedback = 'up' | 'down';

export interface ApiCollectedItem {
  id: string;
  source_url: string;
  source_name: string;
  title: string;
  original_content: string | null;
  ai_summary: string | null;
  relevance_score: number;
  topics: string[];
  status: CollectedStatus;
  curated_content_id: string | null;
  collected_at: string;
  url_hash: string;
  ai_score: number | null;
  ai_score_reason: string | null;
  ai_summary_zh: string | null;
  ai_title_zh: string | null;
  user_feedback: CollectedFeedback | null;
  feedback_at: string | null;
  feed_id: string | null;
}

/** Admin — Flow Run */
export interface ApiFlowRun {
  id: string;
  flow_name: string;
  content_id: string | null;
  input: Record<string, unknown>;
  output: Record<string, unknown> | null;
  status: FlowRunStatus;
  error: string | null;
  attempt: number;
  max_attempts: number;
  started_at: string | null;
  ended_at: string | null;
  created_at: string;
}

export type FlowRunStatus = 'pending' | 'running' | 'completed' | 'failed';

/** Admin — Tracking topics */
export interface ApiTrackingTopic {
  id: string;
  name: string;
  keywords: string[];
  sources: string[];
  enabled: boolean;
  schedule: string;
  created_at: string;
  updated_at: string;
}

export interface ApiCreateTrackingTopicRequest {
  name: string;
  keywords: string[];
  sources: string[];
  enabled?: boolean;
  schedule: string;
}

export interface ApiUpdateTrackingTopicRequest {
  name?: string;
  keywords?: string[];
  sources?: string[];
  enabled?: boolean;
  schedule?: string;
}

/** Admin — Flow Polish */
export interface ApiPolishResult {
  original_body: string;
  polished_body: string;
}

/** Public — Knowledge Graph */
export interface ApiKnowledgeGraph {
  nodes: ApiGraphNode[];
  links: ApiGraphLink[];
}

export interface ApiGraphNode {
  id: string;
  label: string;
  type: string;
  content_type: string | null;
  topic: string | null;
  count: number | null;
}

export interface ApiGraphLink {
  source: string;
  target: string;
  type: string;
  similarity: number | null;
}

/** Public — Related Content */
export interface ApiRelatedContent {
  slug: string;
  title: string;
  excerpt: string;
  type: ContentType;
  similarity: number;
  topics: ApiTopicRef[];
}

export interface ApiTopicRef {
  id: string;
  slug: string;
  name: string;
}

/** Admin — Canonical Tag */
export interface ApiTag {
  id: string;
  slug: string;
  name: string;
  parent_id: string | null;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface ApiCreateTagRequest {
  slug: string;
  name: string;
  parent_id?: string | null;
  description?: string;
}

export interface ApiUpdateTagRequest {
  slug?: string;
  name?: string;
  parent_id?: string | null;
  description?: string;
}

/** Admin — Tag Alias */
export type AliasMatchMethod =
  | 'exact'
  | 'case_insensitive'
  | 'slug'
  | 'manual'
  | 'rejected'
  | 'unmapped';

export interface ApiTagAlias {
  id: string;
  raw_tag: string;
  tag_id: string | null;
  match_method: AliasMatchMethod;
  confirmed: boolean;
  confirmed_at: string | null;
  created_at: string;
}

/** Admin — Tag Operations */
export interface ApiMergeTagsRequest {
  source_id: string;
  target_id: string;
}

export interface ApiMergeResult {
  aliases_moved: number;
  notes_moved: number;
  events_moved: number;
}

export interface ApiBackfillResult {
  notes_processed: number;
  tags_mapped: number;
  tags_unmapped: number;
}

/** Admin — Notion Source */
export interface ApiNotionSource {
  id: string;
  database_id: string;
  name: string;
  description: string;
  sync_mode: NotionSyncMode;
  property_map: Record<string, unknown>;
  poll_interval: string;
  enabled: boolean;
  last_synced_at: string | null;
  created_at: string;
  updated_at: string;
}

export type NotionSyncMode = 'full' | 'events';

export interface ApiDiscoveredDatabase {
  id: string;
  title: string;
}

export type NotionPollInterval =
  | '5 minutes'
  | '10 minutes'
  | '15 minutes'
  | '30 minutes'
  | '1 hour'
  | '2 hours'
  | '4 hours'
  | '6 hours'
  | '12 hours'
  | '24 hours';

export interface ApiCreateNotionSourceRequest {
  database_id: string;
  name: string;
  description?: string;
  sync_mode?: NotionSyncMode;
  property_map?: Record<string, unknown>;
  poll_interval?: NotionPollInterval;
}

export interface ApiUpdateNotionSourceRequest {
  name?: string;
  description?: string;
  sync_mode?: NotionSyncMode;
  property_map?: Record<string, unknown>;
  poll_interval?: NotionPollInterval;
  enabled?: boolean;
}

/** Admin — Spaced Repetition */
export interface ApiSpacedDueResponse {
  intervals: ApiDueInterval[];
  total_due: number;
}

export interface ApiDueInterval {
  note_id: number;
  file_path: string;
  title: string | null;
  type: string | null;
  context: string | null;
  easiness_factor: number;
  interval_days: number;
  repetitions: number;
  last_quality: number | null;
  due_at: string;
  reviewed_at: string | null;
  created_at: string;
}

export interface ApiSpacedInterval {
  note_id: number;
  easiness_factor: number;
  interval_days: number;
  repetitions: number;
  last_quality: number | null;
  due_at: string;
  reviewed_at: string | null;
  created_at: string;
}

export interface ApiSubmitReviewRequest {
  note_id: number;
  quality: number;
}

export interface ApiEnrollRequest {
  note_id: number;
}

/** Admin — Stats */
export interface ApiStatsOverview {
  contents: { total: number; by_status: Record<string, number>; by_type: Record<string, number>; published: number };
  collected: { total: number; by_status: Record<string, number> };
  feeds: { total: number; enabled: number };
  flow_runs: { total: number; by_status: Record<string, number> };
  projects: { total: number; by_status: Record<string, number> };
  reviews: { pending: number; total: number };
  notes: { total: number; by_type: Record<string, number> };
  activity: { total: number; last_24h: number; last_7d: number; by_source: Record<string, number> };
  spaced: { enrolled: number; due: number };
  sources: { total: number; enabled: number };
  tags: { canonical: number; aliases: number; unconfirmed: number };
}

export interface ApiDriftReport {
  period: string;
  areas: ApiAreaDrift[];
}

export interface ApiAreaDrift {
  area: string;
  active_goals: number;
  event_count: number;
  event_percent: number;
  goal_percent: number;
  drift_percent: number;
}

export interface ApiLearningDashboard {
  spaced: { enrolled: number; due: number };
  notes: { total: number; last_week: number; last_month: number; by_type: Record<string, number> };
  activity: { this_week: number; last_week: number; trend: 'up' | 'down' | 'stable' };
  top_tags: ApiTagCount[];
}

export interface ApiTagCount {
  name: string;
  count: number;
}

/** Admin — Activity */
export interface ApiSession {
  start: string;
  end: string;
  duration: string;
  event_count: number;
  sources: string[];
  projects: string[];
}

export interface ApiChangelogDay {
  date: string;
  event_count: number;
  events: ApiChangelogEvent[];
}

export interface ApiChangelogEvent {
  source: string;
  event_type: string;
  project: string | null;
  title: string | null;
  timestamp: string;
}
