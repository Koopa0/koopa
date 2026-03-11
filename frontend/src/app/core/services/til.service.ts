import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import { ContentService } from './content.service';
import type { ApiContent, ApiPaginationMeta } from '../models';

export interface TilsResponse {
  tils: ApiContent[];
  meta: ApiPaginationMeta;
}

@Injectable({ providedIn: 'root' })
export class TilService {
  private readonly content = inject(ContentService);

  getTils(page = 1, perPage = 20): Observable<TilsResponse> {
    return this.content.listByType('til', { page, perPage }).pipe(
      map((res) => ({ tils: res.data, meta: res.meta })),
    );
  }

  getBySlug(slug: string): Observable<ApiContent> {
    return this.content.getBySlug(slug);
  }
}
