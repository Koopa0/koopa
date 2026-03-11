import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import { ContentService } from './content.service';
import type { ApiContent } from '../models';

export interface TagInfo {
  name: string;
  count: number;
}

/** Tag is not a standalone API — aggregated from content list tags field */
@Injectable({ providedIn: 'root' })
export class TagService {
  private readonly content = inject(ContentService);

  /** Get content list by tag */
  getContentsByTag(
    tag: string,
    page = 1,
    perPage = 20,
  ): Observable<{ contents: ApiContent[]; meta: { total: number; page: number; per_page: number; total_pages: number } }> {
    return this.content.listPublished({ tag, page, perPage }).pipe(
      map((res) => ({ contents: res.data, meta: res.meta })),
    );
  }
}
