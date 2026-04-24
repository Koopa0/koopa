import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import { ContentService } from './content.service';
import type {
  ApiContent,
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

  getArticles(filters?: ArticleFilters): Observable<ArticlesResponse> {
    if (filters?.search) {
      return this.content
        .search(filters.search, {
          page: filters?.page,
          perPage: filters?.perPage,
        })
        .pipe(
          map((res) => ({ articles: res.data, meta: res.meta })),
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
      );
  }

  getArticleBySlug(slug: string): Observable<ApiContent> {
    return this.content.getBySlug(slug);
  }

  /** Admin — create article */
  createArticle(request: ApiCreateContentRequest): Observable<ApiContent> {
    return this.content.create({ ...request, type: 'article' });
  }

  /** Admin — update article */
  updateArticle(
    id: string,
    request: ApiUpdateContentRequest,
  ): Observable<ApiContent> {
    return this.content.update(id, request);
  }

  /** Admin — delete article */
  deleteArticle(id: string): Observable<void> {
    return this.content.remove(id);
  }

  /** Admin — publish article */
  publishArticle(id: string): Observable<ApiContent> {
    return this.content.publish(id);
  }
}
