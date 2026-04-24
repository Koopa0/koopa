import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  ApiContent,
  ApiListResponse,
  ApiCreateContentRequest,
  ApiUpdateContentRequest,
  ApiRelatedContent,
  ApiKnowledgeGraph,
  ContentStatus,
  ContentType,
} from '../models';

/** Unified content API — maps to backend /api/contents */
@Injectable({ providedIn: 'root' })
export class ContentService {
  private readonly api = inject(ApiService);

  /** Get published content list (public) */
  listPublished(params?: {
    page?: number;
    perPage?: number;
    type?: ContentType;
    tag?: string;
  }): Observable<ApiListResponse<ApiContent>> {
    const query: Record<string, string | number> = {};
    if (params?.page) query['page'] = params.page;
    if (params?.perPage) query['per_page'] = params.perPage;
    if (params?.type) query['type'] = params.type;
    if (params?.tag) query['tag'] = params.tag;
    return this.api.getListData<ApiContent>('/api/contents', query);
  }

  /** Get single published content by slug (public) */
  getBySlug(slug: string): Observable<ApiContent> {
    return this.api.getData<ApiContent>(`/api/contents/${slug}`);
  }

  /** Get published content list by type (public) */
  listByType(
    type: ContentType,
    params?: { page?: number; perPage?: number },
  ): Observable<ApiListResponse<ApiContent>> {
    const query: Record<string, string | number> = {};
    if (params?.page) query['page'] = params.page;
    if (params?.perPage) query['per_page'] = params.perPage;
    return this.api.getListData<ApiContent>(
      `/api/contents/by-type/${type}`,
      query,
    );
  }

  /** Full-text search (public) */
  search(
    q: string,
    params?: { page?: number; perPage?: number; type?: string },
  ): Observable<ApiListResponse<ApiContent>> {
    const query: Record<string, string | number> = { q };
    if (params?.page) query['page'] = params.page;
    if (params?.perPage) query['per_page'] = params.perPage;
    if (params?.type) query['type'] = params.type;
    return this.api.getListData<ApiContent>('/api/search', query);
  }

  /** Admin — get single content by ID (full fields, no is_public check) */
  adminGet(id: string): Observable<ApiContent> {
    return this.api.getData<ApiContent>(`/api/admin/knowledge/content/${id}`);
  }

  /** Admin — list all contents with optional filters */
  adminList(params?: {
    page?: number;
    perPage?: number;
    type?: ContentType;
    status?: ContentStatus;
    is_public?: boolean;
  }): Observable<ApiListResponse<ApiContent>> {
    const query: Record<string, string | number> = {};
    if (params?.page) query['page'] = params.page;
    if (params?.perPage) query['per_page'] = params.perPage;
    if (params?.type) query['type'] = params.type;
    if (params?.status) query['status'] = params.status;
    if (params?.is_public != null)
      query['is_public'] = String(params.is_public);
    return this.api.getListData<ApiContent>(
      '/api/admin/knowledge/content',
      query,
    );
  }

  /** Admin — create content */
  create(request: ApiCreateContentRequest): Observable<ApiContent> {
    return this.api.postData<ApiContent>(
      '/api/admin/knowledge/content',
      request,
    );
  }

  /** Admin — update content */
  update(id: string, request: ApiUpdateContentRequest): Observable<ApiContent> {
    return this.api.putData<ApiContent>(
      `/api/admin/knowledge/content/${id}`,
      request,
    );
  }

  /** Admin — delete content */
  remove(id: string): Observable<void> {
    return this.api.delete(`/api/admin/knowledge/content/${id}`);
  }

  /** Publish content from review. Backend rejects non-human callers with 403. */
  publish(id: string): Observable<ApiContent> {
    return this.api.postData<ApiContent>(
      `/api/admin/knowledge/content/${id}/publish`,
      {},
    );
  }

  /** Submit a draft for review (draft → review). */
  submitForReview(id: string): Observable<ApiContent> {
    return this.api.postData<ApiContent>(
      `/api/admin/knowledge/content/${id}/submit-for-review`,
      {},
    );
  }

  /**
   * Revert content back to draft, optionally writing reviewer notes
   * into `ai_metadata.review_notes`.
   */
  revertToDraft(id: string, reviewerNotes?: string): Observable<ApiContent> {
    const body = reviewerNotes ? { reviewer_notes: reviewerNotes } : {};
    return this.api.postData<ApiContent>(
      `/api/admin/knowledge/content/${id}/revert-to-draft`,
      body,
    );
  }

  /** Archive content (any status → archived). */
  archive(id: string): Observable<ApiContent> {
    return this.api.postData<ApiContent>(
      `/api/admin/knowledge/content/${id}/archive`,
      {},
    );
  }

  /** Admin — toggle is_public flag */
  setVisibility(id: string, is_public: boolean): Observable<ApiContent> {
    return this.api.patchData<ApiContent>(
      `/api/admin/knowledge/content/${id}/is-public`,
      { is_public },
    );
  }

  /** Public — get related content by slug */
  getRelated(slug: string): Observable<ApiRelatedContent[]> {
    return this.api.getData<ApiRelatedContent[]>(
      `/api/contents/related/${slug}`,
    );
  }

  /** Public — get knowledge graph (rate-limited) */
  getKnowledgeGraph(): Observable<ApiKnowledgeGraph> {
    return this.api.getData<ApiKnowledgeGraph>('/api/knowledge-graph');
  }
}
