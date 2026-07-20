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

/** Backend Content object (snake_case, matches internal/content/content.go::Content).
 *
 * Schema truth: migrations/001_initial.up.sql::contents.
 */
export interface ApiContent {
  id: string;
  slug: string;
  title: string;
  body: string;
  excerpt: string;
  type: ContentType;
  status: ContentStatus;
  topics: ApiTopicRef[];
  cover_image: string | null;
  series_id: string | null;
  series_order: number | null;
  is_public: boolean;
  reading_time_min: number;
  /** Proposing agent for agent-submitted content. Null on legacy owner-authored rows. */
  created_by?: string | null;
  /** The proposing agent's rationale, shown in the review queue. Null on legacy owner-authored rows. */
  proposal_rationale?: string | null;
  /** Owner's revision note when sending content back from review. Populated only when status=changes_requested. */
  review_note?: string | null;
  /** Authenticated-only provenance for a Vault-authored publication snapshot. */
  source?: {
    vault_path: string;
    git_blob_sha: string;
  } | null;
  /** Authenticated-only metadata for the current withdrawal, when present. */
  withdrawal?: {
    reason: string;
    withdrawn_at: string;
  } | null;
  published_at: string | null;
  created_at: string;
  updated_at: string;
}

// Backend content_type enum (migrations/001_initial.up.sql).
export type ContentType = 'article' | 'essay' | 'build-log' | 'til' | 'digest';

export type ContentStatus =
  | 'draft'
  | 'review'
  | 'changes_requested'
  | 'published'
  | 'archived';

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

/**
 * Lean topic reference embedded on content rows (Go `content.TopicRef`).
 * Only id / slug / name are on this wire — distinct from the full ApiTopic
 * returned by the topics endpoint.
 */
export interface ApiTopicRef {
  id: string;
  slug: string;
  name: string;
}

/** Backend Project object — planning projection (PARA). */
export interface ApiProject {
  id: string;
  slug: string;
  title: string;
  description: string;
  status: ProjectStatus;
  repo: string | null;
  area: string;
  deadline: string | null;
  last_activity_at: string | null;
  created_at: string;
  updated_at: string;
}

export type ProjectStatus =
  | 'planned'
  | 'in_progress'
  | 'on_hold'
  | 'completed'
  | 'maintained'
  | 'archived';

export type GoalStatus =
  | 'not_started'
  | 'in_progress'
  | 'done'
  | 'abandoned'
  | 'on_hold';

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

/** Admin — Update legacy, source-unbound content fields. */
export interface ApiUpdateContentRequest {
  slug?: string;
  title?: string;
  body?: string;
  excerpt?: string;
  topic_ids?: string[];
  cover_image?: string;
  series_id?: string;
  series_order?: number;
  reading_time_min?: number;
}
