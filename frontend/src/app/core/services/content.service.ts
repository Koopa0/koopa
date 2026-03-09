import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import { ApiService } from './api.service';
import type {
  ApiContent,
  ApiListResponse,
  ApiCreateContentRequest,
  ApiUpdateContentRequest,
  ContentType,
} from '../models';

/** 統一內容 API — 對應後端 /api/contents */
@Injectable({ providedIn: 'root' })
export class ContentService {
  private readonly api = inject(ApiService);

  /** 取得已發布的內容列表（公開） */
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

  /** 依 slug 取得單篇已發布內容（公開） */
  getBySlug(slug: string): Observable<ApiContent> {
    return this.api.getData<ApiContent>(`/api/contents/${slug}`);
  }

  /** 依類型取得已發布內容列表（公開） */
  listByType(
    type: ContentType,
    params?: { page?: number; perPage?: number },
  ): Observable<ApiListResponse<ApiContent>> {
    const query: Record<string, string | number> = {};
    if (params?.page) query['page'] = params.page;
    if (params?.perPage) query['per_page'] = params.perPage;
    return this.api.getListData<ApiContent>(`/api/contents/type/${type}`, query);
  }

  /** 全文搜尋（公開） */
  search(
    q: string,
    params?: { page?: number; perPage?: number },
  ): Observable<ApiListResponse<ApiContent>> {
    const query: Record<string, string | number> = { q };
    if (params?.page) query['page'] = params.page;
    if (params?.perPage) query['per_page'] = params.perPage;
    return this.api.getListData<ApiContent>('/api/search', query);
  }

  /** Admin — 建立內容 */
  create(request: ApiCreateContentRequest): Observable<ApiContent> {
    return this.api.postData<ApiContent>('/api/admin/contents', request);
  }

  /** Admin — 更新內容 */
  update(id: string, request: ApiUpdateContentRequest): Observable<ApiContent> {
    return this.api.putData<ApiContent>(`/api/admin/contents/${id}`, request);
  }

  /** Admin — 刪除內容 */
  remove(id: string): Observable<void> {
    return this.api.delete(`/api/admin/contents/${id}`);
  }

  /** Admin — 發布內容 */
  publish(id: string): Observable<ApiContent> {
    return this.api.postData<ApiContent>(
      `/api/admin/contents/${id}/publish`,
      {},
    );
  }
}
