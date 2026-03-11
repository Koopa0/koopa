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
  created_at: string;
  updated_at: string;
}

export type FeedSchedule = 'hourly_4' | 'daily' | 'weekly';

export interface ApiCreateFeedRequest {
  url: string;
  name: string;
  schedule: FeedSchedule;
  topics?: string[];
}

export interface ApiUpdateFeedRequest {
  url?: string;
  name?: string;
  schedule?: string;
  topics?: string[];
  enabled?: boolean;
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
