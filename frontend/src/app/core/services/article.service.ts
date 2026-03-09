import { Injectable, inject, signal, computed } from '@angular/core';
import { Observable, map, tap, catchError, throwError } from 'rxjs';
import { ContentService } from './content.service';
import type {
  ApiContent,
  ApiListResponse,
  ApiPaginationMeta,
  ApiCreateContentRequest,
  ApiUpdateContentRequest,
} from '../models';

export interface ArticlesResponse {
  articles: ApiContent[];
  meta: ApiPaginationMeta;
}

export interface ArticleFilters {
  tag?: string;
  search?: string;
  page?: number;
  perPage?: number;
}

@Injectable({ providedIn: 'root' })
export class ArticleService {
  private readonly content = inject(ContentService);

  private readonly _loading = signal(false);
  private readonly _error = signal<string | null>(null);

  readonly loading = this._loading.asReadonly();
  readonly errorMessage = this._error.asReadonly();

  getArticles(filters?: ArticleFilters): Observable<ArticlesResponse> {
    this._loading.set(true);
    this._error.set(null);

    if (filters?.search) {
      return this.content
        .search(filters.search, {
          page: filters?.page,
          perPage: filters?.perPage,
        })
        .pipe(
          map((res) => ({ articles: res.data, meta: res.meta })),
          tap(() => this._loading.set(false)),
          catchError((err) => {
            this._loading.set(false);
            this._error.set('搜尋文章失敗');
            return throwError(() => err);
          }),
        );
    }

    return this.content
      .listPublished({
        type: 'article',
        tag: filters?.tag,
        page: filters?.page,
        perPage: filters?.perPage,
      })
      .pipe(
        map((res) => ({ articles: res.data, meta: res.meta })),
        tap(() => this._loading.set(false)),
        catchError((err) => {
          this._loading.set(false);
          this._error.set('載入文章列表失敗');
          return throwError(() => err);
        }),
      );
  }

  getArticleBySlug(slug: string): Observable<ApiContent> {
    this._loading.set(true);
    this._error.set(null);

    return this.content.getBySlug(slug).pipe(
      tap(() => this._loading.set(false)),
      catchError((err) => {
        this._loading.set(false);
        this._error.set('文章不存在');
        return throwError(() => err);
      }),
    );
  }

  /** Admin — 建立文章 */
  createArticle(request: ApiCreateContentRequest): Observable<ApiContent> {
    return this.content.create({ ...request, type: 'article' });
  }

  /** Admin — 更新文章 */
  updateArticle(
    id: string,
    request: ApiUpdateContentRequest,
  ): Observable<ApiContent> {
    return this.content.update(id, request);
  }

  /** Admin — 刪除文章 */
  deleteArticle(id: string): Observable<void> {
    return this.content.remove(id);
  }

  /** Admin — 發布文章 */
  publishArticle(id: string): Observable<ApiContent> {
    return this.content.publish(id);
  }
}
