import { Injectable, inject, signal } from '@angular/core';
import { Observable, map, tap, catchError, throwError } from 'rxjs';
import { ContentService } from './content.service';
import type { ApiContent } from '../models';

export interface TagInfo {
  name: string;
  count: number;
}

/** Tag 不是獨立 API — 從內容列表的 tags 欄位聚合 */
@Injectable({ providedIn: 'root' })
export class TagService {
  private readonly content = inject(ContentService);

  private readonly _loading = signal(false);
  private readonly _error = signal<string | null>(null);

  readonly loading = this._loading.asReadonly();
  readonly errorMessage = this._error.asReadonly();

  /** 依 tag 取得內容列表 */
  getContentsByTag(
    tag: string,
    page = 1,
    perPage = 20,
  ): Observable<{ contents: ApiContent[]; meta: { total: number; page: number; per_page: number; total_pages: number } }> {
    this._loading.set(true);
    this._error.set(null);

    return this.content.listPublished({ tag, page, perPage }).pipe(
      map((res) => ({ contents: res.data, meta: res.meta })),
      tap(() => this._loading.set(false)),
      catchError((err) => {
        this._loading.set(false);
        this._error.set('載入標籤內容失敗');
        return throwError(() => err);
      }),
    );
  }
}
