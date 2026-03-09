import { Injectable, inject, signal } from '@angular/core';
import { Observable, map, tap, catchError, throwError } from 'rxjs';
import { ContentService } from './content.service';
import type { ApiContent, ApiPaginationMeta } from '../models';

export interface TilsResponse {
  tils: ApiContent[];
  meta: ApiPaginationMeta;
}

@Injectable({ providedIn: 'root' })
export class TilService {
  private readonly content = inject(ContentService);

  private readonly _loading = signal(false);
  private readonly _error = signal<string | null>(null);

  readonly loading = this._loading.asReadonly();
  readonly errorMessage = this._error.asReadonly();

  getTils(page = 1, perPage = 20): Observable<TilsResponse> {
    this._loading.set(true);
    this._error.set(null);

    return this.content.listByType('til', { page, perPage }).pipe(
      map((res) => ({ tils: res.data, meta: res.meta })),
      tap(() => this._loading.set(false)),
      catchError((err) => {
        this._loading.set(false);
        this._error.set('載入學習筆記失敗');
        return throwError(() => err);
      }),
    );
  }

  getBySlug(slug: string): Observable<ApiContent> {
    this._loading.set(true);
    this._error.set(null);

    return this.content.getBySlug(slug).pipe(
      tap(() => this._loading.set(false)),
      catchError((err) => {
        this._loading.set(false);
        this._error.set('學習筆記不存在');
        return throwError(() => err);
      }),
    );
  }
}
