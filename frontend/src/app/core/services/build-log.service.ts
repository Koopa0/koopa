import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import { ContentService } from './content.service';
import type { ApiContent, ApiPaginationMeta } from '../models';

export interface BuildLogsResponse {
  buildLogs: ApiContent[];
  meta: ApiPaginationMeta;
}

@Injectable({ providedIn: 'root' })
export class BuildLogService {
  private readonly content = inject(ContentService);

  getBuildLogs(page = 1, perPage = 10): Observable<BuildLogsResponse> {
    return this.content.listByType('build-log', { page, perPage }).pipe(
      map((res) => ({ buildLogs: res.data, meta: res.meta })),
    );
  }

  getBySlug(slug: string): Observable<ApiContent> {
    return this.content.getBySlug(slug);
  }
}
