import { Injectable, inject } from '@angular/core';
import { Observable, map } from 'rxjs';
import { ContentService } from './content.service';
import type { ApiContent, ApiPaginationMeta } from '../models';

export interface NotesResponse {
  notes: ApiContent[];
  meta: ApiPaginationMeta;
}

@Injectable({ providedIn: 'root' })
export class NoteService {
  private readonly content = inject(ContentService);

  getNotes(page = 1, perPage = 20): Observable<NotesResponse> {
    return this.content.listByType('note', { page, perPage }).pipe(
      map((res) => ({ notes: res.data, meta: res.meta })),
    );
  }

  getBySlug(slug: string): Observable<ApiContent> {
    return this.content.getBySlug(slug);
  }
}
