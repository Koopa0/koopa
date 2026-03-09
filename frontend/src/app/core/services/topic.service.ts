import { Injectable, inject, signal } from '@angular/core';
import { Observable, map, tap, catchError, throwError } from 'rxjs';
import { ApiService } from './api.service';
import type { ApiTopic, ApiContent, ApiPaginationMeta } from '../models';

export interface TopicWithContents {
  topic: ApiTopic;
  contents: ApiContent[];
  meta: ApiPaginationMeta;
}

@Injectable({ providedIn: 'root' })
export class TopicService {
  private readonly api = inject(ApiService);

  private readonly _loading = signal(false);
  private readonly _error = signal<string | null>(null);

  readonly loading = this._loading.asReadonly();
  readonly errorMessage = this._error.asReadonly();

  /** 取得所有主題（公開） */
  getAllTopics(): Observable<ApiTopic[]> {
    this._loading.set(true);
    this._error.set(null);

    return this.api.getData<ApiTopic[]>('/api/topics').pipe(
      tap(() => this._loading.set(false)),
      catchError((err) => {
        this._loading.set(false);
        this._error.set('載入主題失敗');
        return throwError(() => err);
      }),
    );
  }

  /** 取得單一主題及其內容（公開） */
  getTopicBySlug(
    slug: string,
    params?: { page?: number; perPage?: number },
  ): Observable<TopicWithContents> {
    this._loading.set(true);
    this._error.set(null);

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
        tap(() => this._loading.set(false)),
        catchError((err) => {
          this._loading.set(false);
          this._error.set('主題不存在');
          return throwError(() => err);
        }),
      );
  }
}
