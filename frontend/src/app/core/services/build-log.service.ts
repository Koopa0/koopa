import { Injectable, inject, signal } from '@angular/core';
import { Observable, map, tap, catchError, throwError } from 'rxjs';
import { ContentService } from './content.service';
import type { ApiContent, ApiPaginationMeta } from '../models';

export interface BuildLogsResponse {
  buildLogs: ApiContent[];
  meta: ApiPaginationMeta;
}

@Injectable({ providedIn: 'root' })
export class BuildLogService {
  private readonly content = inject(ContentService);

  private readonly _loading = signal(false);
  private readonly _error = signal<string | null>(null);

  readonly loading = this._loading.asReadonly();
  readonly errorMessage = this._error.asReadonly();

  getBuildLogs(page = 1, perPage = 10): Observable<BuildLogsResponse> {
    this._loading.set(true);
    this._error.set(null);

    return this.content.listByType('build-log', { page, perPage }).pipe(
      map((res) => ({ buildLogs: res.data, meta: res.meta })),
      tap(() => this._loading.set(false)),
      catchError((err) => {
        this._loading.set(false);
        this._error.set('載入開發紀錄失敗');
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
        this._error.set('開發紀錄不存在');
        return throwError(() => err);
      }),
    );
  }
}
