import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import { ApiService } from './api.service';
import type { ApiTopic, ApiContent, ApiPaginationMeta } from '../models';

export interface TopicWithContents {
  topic: ApiTopic;
  contents: ApiContent[];
  meta: ApiPaginationMeta;
}

/** Partial update payload — only provided fields change. */
export interface TopicUpdateRequest {
  slug?: string;
  name?: string;
  description?: string;
  icon?: string;
  sort_order?: number;
}

@Injectable({ providedIn: 'root' })
export class TopicService {
  private readonly api = inject(ApiService);

  /** Get all topics (public) */
  getAllTopics(): Observable<ApiTopic[]> {
    return this.api.getData<ApiTopic[]>('/api/topics');
  }

  /** Admin — list topics (same payload as the public list, auth-gated) */
  adminList(): Observable<ApiTopic[]> {
    return this.api.getData<ApiTopic[]>('/api/admin/knowledge/topics');
  }

  /** Admin — update a topic (rename, description, icon, sort order) */
  adminUpdate(id: string, body: TopicUpdateRequest): Observable<ApiTopic> {
    return this.api.putData<ApiTopic>(
      `/api/admin/knowledge/topics/${id}`,
      body,
    );
  }

  /** Get single topic with its contents by slug (public) */
  getTopicBySlug(
    slug: string,
    params?: { page?: number; perPage?: number },
  ): Observable<TopicWithContents> {
    const query: Record<string, string | number> = {};
    if (params?.page) query['page'] = params.page;
    if (params?.perPage) query['per_page'] = params.perPage;

    return this.api
      .getList<never>(`/api/topics/${slug}`, query)
      .pipe(
        map((res) => {
          const raw = res as unknown as {
            data: { topic: ApiTopic; contents: ApiContent[] };
            meta: ApiPaginationMeta;
          };
          return {
            topic: raw.data.topic,
            contents: raw.data.contents,
            meta: raw.meta,
          };
        }),
      );
  }
}
