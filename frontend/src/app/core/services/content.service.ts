import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  ApiContent,
  ApiListResponse,
  ApiUpdateContentRequest,
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

  /** Send content back from review to the agent for revision, with a required reason. */
  sendBack(id: string, reviewNote: string): Observable<ApiContent> {
    return this.api.postData<ApiContent>(
      `/api/admin/knowledge/content/${id}/send-back`,
      { review_note: reviewNote },
    );
  }

  /** Revert content back to draft. The handler takes no body. */
  revertToDraft(id: string): Observable<ApiContent> {
    return this.api.postData<ApiContent>(
      `/api/admin/knowledge/content/${id}/revert-to-draft`,
      {},
    );
  }

  /** Archive content (any status → archived). */
  archive(id: string): Observable<ApiContent> {
    return this.api.postData<ApiContent>(
      `/api/admin/knowledge/content/${id}/archive`,
      {},
    );
  }

  /** Withdraw a public snapshot with the owner's durable reason. */
  withdraw(id: string, reason: string): Observable<ApiContent> {
    return this.api.postData<ApiContent>(
      `/api/admin/knowledge/content/${id}/withdraw`,
      { reason },
    );
  }

  /** Restore a withdrawn snapshot to the public surface. */
  restore(id: string): Observable<ApiContent> {
    return this.api.postData<ApiContent>(
      `/api/admin/knowledge/content/${id}/restore`,
      {},
    );
  }
}
