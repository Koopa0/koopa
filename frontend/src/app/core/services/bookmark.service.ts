import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { ApiListResponse } from '../models/api.model';
import type { BookmarkDetail } from '../models/workbench.model';

export interface BookmarkUpdateRequest {
  title?: string;
  note?: string;
  topic_slug?: string;
  tags?: string[];
  is_public?: boolean;
}

export interface BookmarkCreateRequest {
  title: string;
  url: string;
  note?: string;
  topic_slug?: string;
  tags?: string[];
}

/**
 * Bookmark service — public list (`/api/bookmarks`) plus the admin
 * CRUD surface (`/api/admin/knowledge/bookmarks/*`).
 */
@Injectable({ providedIn: 'root' })
export class BookmarkService {
  private readonly api = inject(ApiService);

  /** Public list — used by the public bookmarks page. */
  list(params?: {
    page?: number;
    perPage?: number;
  }): Observable<ApiListResponse<BookmarkDetail>> {
    const query: Record<string, string | number> = {};
    if (params?.page) query['page'] = params.page;
    if (params?.perPage) query['per_page'] = params.perPage;
    return this.api.getListData<BookmarkDetail>('/api/bookmarks', query);
  }

  /** Admin list — includes private bookmarks and the `actor` column. */
  adminList(params?: {
    page?: number;
    perPage?: number;
  }): Observable<ApiListResponse<BookmarkDetail>> {
    const query: Record<string, string | number> = {};
    if (params?.page) query['page'] = params.page;
    if (params?.perPage) query['per_page'] = params.perPage;
    return this.api.getListData<BookmarkDetail>(
      '/api/admin/knowledge/bookmarks',
      query,
    );
  }

  get(id: string): Observable<BookmarkDetail> {
    return this.api.getData<BookmarkDetail>(
      `/api/admin/knowledge/bookmarks/${id}`,
    );
  }

  update(id: string, body: BookmarkUpdateRequest): Observable<BookmarkDetail> {
    return this.api.putData<BookmarkDetail>(
      `/api/admin/knowledge/bookmarks/${id}`,
      body,
    );
  }

  create(body: BookmarkCreateRequest): Observable<BookmarkDetail> {
    return this.api.postData<BookmarkDetail>(
      '/api/admin/knowledge/bookmarks',
      body,
    );
  }

  remove(id: string): Observable<void> {
    return this.api.delete(`/api/admin/knowledge/bookmarks/${id}`);
  }
}
