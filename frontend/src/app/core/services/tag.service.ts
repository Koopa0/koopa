import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';

/** Canonical tag row from the tags table. */
export interface AdminTag {
  id: string;
  slug: string;
  name: string;
  parent_id?: string;
  description: string;
  created_at: string;
  updated_at: string;
}

/** Partial update payload — at least one field must be provided. */
export interface TagUpdateRequest {
  slug?: string;
  name?: string;
  description?: string;
}

/** Row counts moved off the source tag during a merge. */
export interface TagMergeResult {
  aliases_moved: number;
  content_tags_moved: number;
}

/**
 * Tag service — canonical tag administration.
 *
 * The list endpoint returns bare tag rows; per-tag usage counts are
 * not exposed by the backend. Merge reassigns every alias and
 * content link from the source tag to the target, then deletes the
 * source.
 */
@Injectable({ providedIn: 'root' })
export class TagService {
  private readonly api = inject(ApiService);

  list(): Observable<AdminTag[]> {
    return this.api.getData<AdminTag[]>('/api/admin/knowledge/tags');
  }

  update(id: string, body: TagUpdateRequest): Observable<AdminTag> {
    return this.api.putData<AdminTag>(`/api/admin/knowledge/tags/${id}`, body);
  }

  merge(sourceId: string, targetId: string): Observable<TagMergeResult> {
    return this.api.postData<TagMergeResult>('/api/admin/knowledge/tags/merge', {
      source_id: sourceId,
      target_id: targetId,
    });
  }
}
