import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  ApiTag,
  ApiTagAlias,
  ApiCreateTagRequest,
  ApiUpdateTagRequest,
  ApiMergeTagsRequest,
  ApiMergeResult,
  ApiBackfillResult,
} from '../models';

/** Admin CRUD for canonical tags and tag aliases */
@Injectable({ providedIn: 'root' })
export class TagAdminService {
  private readonly api = inject(ApiService);

  // ─── Canonical Tags ───

  getTags(): Observable<ApiTag[]> {
    return this.api.getData<ApiTag[]>('/api/admin/tags');
  }

  createTag(body: ApiCreateTagRequest): Observable<ApiTag> {
    return this.api.postData<ApiTag>('/api/admin/tags', body);
  }

  updateTag(id: string, body: ApiUpdateTagRequest): Observable<ApiTag> {
    return this.api.putData<ApiTag>(`/api/admin/tags/${id}`, body);
  }

  deleteTag(id: string): Observable<void> {
    return this.api.delete(`/api/admin/tags/${id}`);
  }

  // ─── Tag Aliases ───

  getAliases(unmapped?: boolean): Observable<ApiTagAlias[]> {
    const params: Record<string, string> = {};
    if (unmapped) {
      params['unmapped'] = 'true';
    }
    return this.api.getData<ApiTagAlias[]>('/api/admin/aliases', params);
  }

  mapAlias(aliasId: string, tagId: string): Observable<ApiTagAlias> {
    return this.api.postData<ApiTagAlias>(
      `/api/admin/aliases/${aliasId}/map`,
      { tag_id: tagId },
    );
  }

  confirmAlias(aliasId: string): Observable<ApiTagAlias> {
    return this.api.postData<ApiTagAlias>(
      `/api/admin/aliases/${aliasId}/confirm`,
      {},
    );
  }

  rejectAlias(aliasId: string): Observable<ApiTagAlias> {
    return this.api.postData<ApiTagAlias>(
      `/api/admin/aliases/${aliasId}/reject`,
      {},
    );
  }

  deleteAlias(aliasId: string): Observable<void> {
    return this.api.delete(`/api/admin/aliases/${aliasId}`);
  }

  // ─── Tag Operations ───

  mergeTags(body: ApiMergeTagsRequest): Observable<ApiMergeResult> {
    return this.api.postData<ApiMergeResult>('/api/admin/tags/merge', body);
  }

  backfillTags(): Observable<ApiBackfillResult> {
    return this.api.postData<ApiBackfillResult>('/api/admin/tags/backfill', {});
  }
}
