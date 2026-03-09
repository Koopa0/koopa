export interface Article {
  id: string;
  title: string;
  slug: string;
  excerpt: string;
  content: string;
  coverImage?: string;
  tags: string[];
  publishedAt: Date;
  updatedAt: Date;
  readingTime: number;
  viewCount: number;
  status: ArticleStatus;
  seriesId?: string;
  seriesOrder?: number;
  seoDescription?: string;
  seoKeywords?: string[];
}

export interface ArticleListItem {
  id: string;
  title: string;
  slug: string;
  excerpt: string;
  coverImage?: string;
  tags: string[];
  publishedAt: Date;
  readingTime: number;
  viewCount: number;
  seriesId?: string;
  seriesOrder?: number;
}

export interface CreateArticleRequest {
  title: string;
  content: string;
  excerpt: string;
  tags: string[];
  coverImage?: string;
  seriesId?: string;
  seriesOrder?: number;
  seoDescription?: string;
  seoKeywords?: string[];
  status: ArticleStatus;
}

export interface UpdateArticleRequest extends Partial<CreateArticleRequest> {
  id: string;
}

export enum ArticleStatus {
  DRAFT = 'draft',
  PUBLISHED = 'published',
  ARCHIVED = 'archived'
}

export interface ArticlesResponse {
  articles: ArticleListItem[];
  total: number;
  page: number;
  limit: number;
  hasNext: boolean;
  hasPrevious: boolean;
}

export interface ArticleFilters {
  tags?: string[];
  search?: string;
  status?: ArticleStatus;
  page?: number;
  limit?: number;
  sortBy?: 'publishedAt' | 'updatedAt' | 'viewCount' | 'title';
  sortOrder?: 'asc' | 'desc';
}