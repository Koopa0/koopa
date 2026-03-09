export type BuildLogStatus = 'draft' | 'published' | 'archived';

export interface BuildLog {
  id: string;
  slug: string;
  projectId: string;
  title: string;
  excerpt: string;
  content: string;
  coverImage?: string;
  tags: string[];
  publishedAt: Date;
  updatedAt: Date;
  readingTime: number;
  status: BuildLogStatus;
}

export interface BuildLogListItem {
  id: string;
  slug: string;
  projectId: string;
  title: string;
  excerpt: string;
  coverImage?: string;
  tags: string[];
  publishedAt: Date;
  readingTime: number;
}

export interface BuildLogsResponse {
  buildLogs: BuildLogListItem[];
  total: number;
  page: number;
  limit: number;
  hasNext: boolean;
  hasPrevious: boolean;
}

export interface CreateBuildLogRequest {
  title: string;
  projectId: string;
  content: string;
  excerpt: string;
  tags: string[];
  coverImage?: string;
  status: BuildLogStatus;
}

export interface UpdateBuildLogRequest extends Partial<CreateBuildLogRequest> {
  id: string;
}
