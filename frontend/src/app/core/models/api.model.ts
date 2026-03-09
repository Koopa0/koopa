/** API 統一回應格式 — 對應後端 JSON 結構 */

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

/** 後端 Content 物件（snake_case，對應 API 回應） */
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

/** 後端 Topic 物件 */
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

/** 後端 Project 物件 */
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

/** 後端 Auth 回應 */
export interface ApiLoginRequest {
  email: string;
  password: string;
}

export interface ApiTokenResponse {
  access_token: string;
  refresh_token: string;
}

/** JWT payload（後端 Claims struct） */
export interface JwtPayload {
  user_id: string;
  email: string;
  role: string;
  exp: number;
  iat: number;
}

/** Admin — 建立/更新 Content 請求 */
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

/** Admin — 建立/更新 Project 請求 */
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
  sort_order?: number;
  status?: ProjectStatus;
}

export interface ApiUpdateProjectRequest
  extends Partial<ApiCreateProjectRequest> {}

/** Admin — 建立/更新 Topic 請求 */
export interface ApiCreateTopicRequest {
  slug: string;
  name: string;
  description?: string;
  icon?: string;
  sort_order?: number;
}

export interface ApiUpdateTopicRequest
  extends Partial<ApiCreateTopicRequest> {}

/** Admin — Review 審核 */
export interface ApiReviewItem {
  id: string;
  content_id: string;
  review_level: ReviewLevel;
  status: 'pending' | 'approved' | 'rejected';
  reviewer_notes: string | null;
  content_title: string;
  content_slug: string;
  content_type: ContentType;
  submitted_at: string;
  reviewed_at: string | null;
}

/** Admin — Collected 收集資料 */
export interface ApiCollectedItem {
  id: string;
  source_url: string;
  source_name: string;
  title: string;
  original_content: string;
  ai_summary: string | null;
  relevance_score: number;
  topics: string[];
  status: 'unread' | 'read' | 'curated' | 'ignored';
  curated_content_id: string | null;
  collected_at: string;
}

/** Admin — Tracking 追蹤主題 */
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
