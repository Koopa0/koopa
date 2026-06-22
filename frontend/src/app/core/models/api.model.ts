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
  ai_metadata: Record<string, unknown> | null;
  reading_time_min: number;
  /** Proposing agent for agent-pushed content (MCP propose_content). Null for owner/admin-authored content. */
  created_by?: string | null;
  /** The proposing agent's rationale, shown in the review queue. Null for admin-authored content. */
  proposal_rationale?: string | null;
  published_at: string | null;
  created_at: string;
  updated_at: string;
}

// Backend content_type enum (migrations/001_initial.up.sql).
export type ContentType = 'article' | 'essay' | 'build-log' | 'til' | 'digest';

export type ContentStatus = 'draft' | 'review' | 'published' | 'archived';

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
  is_public: boolean;
  sort_order: number;
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

/**
 * Public portfolio listing (matches internal/project/project.go::PublicListing).
 *
 * Served by GET /api/portfolio — the rich public project profile
 * (role, tech stack, highlights, problem/solution/architecture/results).
 * GET /api/projects/{slug} returns only the bare project row, so public
 * project pages compose from this shape. Optional fields are omitted by
 * the backend when unset (Go pointer + omitempty).
 */
export interface ApiPortfolioProject {
  id: string;
  slug: string;
  title: string;
  description: string;
  status: ProjectStatus;
  repo?: string;
  deadline?: string;
  last_activity_at?: string;
  long_description?: string;
  role?: string;
  tech_stack: string[];
  highlights: string[];
  problem?: string;
  solution?: string;
  architecture?: string;
  results?: string;
  github_url?: string;
  live_url?: string;
  cover_image?: string;
  featured: boolean;
  sort_order: number;
  updated_at: string;
}

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

/** Admin — Create/Update Content request */
export interface ApiCreateContentRequest {
  slug: string;
  title: string;
  body?: string;
  excerpt?: string;
  type: ContentType;
  status?: ContentStatus;
  topic_ids?: string[];
  cover_image?: string;
  source?: string;
  source_type?: string;
  series_id?: string;
  series_order?: number;
  ai_metadata?: Record<string, unknown>;
  reading_time_min?: number;
  is_public?: boolean;
}

export interface ApiUpdateContentRequest {
  slug?: string;
  title?: string;
  body?: string;
  excerpt?: string;
  topic_ids?: string[];
  cover_image?: string;
  status?: ContentStatus;
  series_id?: string;
  series_order?: number;
  ai_metadata?: Record<string, unknown>;
  reading_time_min?: number;
  is_public?: boolean;
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
