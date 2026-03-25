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
  ContentType,
  ContentVisibility,
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
    return this.api.getListData<ApiContent>(`/api/contents/by-type/${type}`, query);
  }

  /** Full-text search (public) */
  search(
    q: string,
    params?: { page?: number; perPage?: number },
  ): Observable<ApiListResponse<ApiContent>> {
    const query: Record<string, string | number> = { q };
    if (params?.page) query['page'] = params.page;
    if (params?.perPage) query['per_page'] = params.perPage;
    return this.api.getListData<ApiContent>('/api/search', query);
  }

  /** Admin — list all contents (no visibility/status filter) */
  adminList(params?: {
    page?: number;
    perPage?: number;
    type?: ContentType;
    visibility?: ContentVisibility;
  }): Observable<ApiListResponse<ApiContent>> {
    const query: Record<string, string | number> = {};
    if (params?.page) query['page'] = params.page;
    if (params?.perPage) query['per_page'] = params.perPage;
    if (params?.type) query['type'] = params.type;
    if (params?.visibility) query['visibility'] = params.visibility;
    return this.api.getListData<ApiContent>('/api/admin/contents', query);
  }

  /** Admin — create content */
  create(request: ApiCreateContentRequest): Observable<ApiContent> {
    return this.api.postData<ApiContent>('/api/admin/contents', request);
  }

  /** Admin — update content */
  update(id: string, request: ApiUpdateContentRequest): Observable<ApiContent> {
    return this.api.putData<ApiContent>(`/api/admin/contents/${id}`, request);
  }

  /** Admin — delete content */
  remove(id: string): Observable<void> {
    return this.api.delete(`/api/admin/contents/${id}`);
  }

  /** Admin — publish content */
  publish(id: string): Observable<ApiContent> {
    return this.api.postData<ApiContent>(
      `/api/admin/contents/${id}/publish`,
      {},
    );
  }

  /** Admin — toggle visibility */
  setVisibility(id: string, visibility: ContentVisibility): Observable<ApiContent> {
    return this.api.patchData<ApiContent>(`/api/admin/contents/${id}/visibility`, { visibility });
  }

  /** Public — get related content by slug */
  getRelated(slug: string): Observable<ApiRelatedContent[]> {
    return this.api.getData<ApiRelatedContent[]>(`/api/contents/related/${slug}`);
  }

  /** Public — get knowledge graph (rate-limited) */
  getKnowledgeGraph(): Observable<ApiKnowledgeGraph> {
    return this.api.getData<ApiKnowledgeGraph>('/api/knowledge-graph');
  }
}
