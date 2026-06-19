import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { NoteKind, NoteMaturity } from '../models/api.model';

/** Row shape returned by the list endpoint (metadata only, no body). */
export interface NoteRow {
  id: string;
  slug: string;
  title: string;
  kind: NoteKind;
  maturity: NoteMaturity;
  /** Authoring agent identity — the `created_by` wire field (e.g. human, hermes). */
  created_by: string;
  created_at: string;
  updated_at: string;
}

/** Single-note shape: row fields plus the markdown body. */
export interface NoteDetail extends NoteRow {
  body: string;
}

export interface NoteListQuery {
  kind?: NoteKind;
  maturity?: NoteMaturity;
  q?: string;
}

export interface NoteCreateRequest {
  title: string;
  body: string;
  kind: NoteKind;
  maturity?: NoteMaturity;
  slug?: string;
}

export interface NoteUpdateRequest {
  title?: string;
  body?: string;
  kind?: NoteKind;
}

/**
 * Note service — wraps the `notes` table (Zettelkasten).
 *
 * Maturity transitions go through `POST /:id/maturity`, not the
 * general `PUT /:id`, so the audit trail stays distinct from routine
 * edits.
 */
@Injectable({ providedIn: 'root' })
export class NoteService {
  private readonly api = inject(ApiService);

  list(query: NoteListQuery = {}): Observable<NoteRow[]> {
    const params: Record<string, string> = {};
    if (query.kind) params['kind'] = query.kind;
    if (query.maturity) params['maturity'] = query.maturity;
    if (query.q) params['q'] = query.q;
    return this.api.getData<NoteRow[]>('/api/admin/knowledge/notes', params);
  }

  get(id: string): Observable<NoteDetail> {
    return this.api.getData<NoteDetail>(`/api/admin/knowledge/notes/${id}`);
  }

  create(body: NoteCreateRequest): Observable<NoteDetail> {
    return this.api.postData<NoteDetail>('/api/admin/knowledge/notes', body);
  }

  update(id: string, body: NoteUpdateRequest): Observable<NoteDetail> {
    return this.api.putData<NoteDetail>(
      `/api/admin/knowledge/notes/${id}`,
      body,
    );
  }

  updateMaturity(id: string, maturity: NoteMaturity): Observable<NoteDetail> {
    return this.api.postData<NoteDetail>(
      `/api/admin/knowledge/notes/${id}/maturity`,
      { maturity },
    );
  }

  remove(id: string): Observable<void> {
    return this.api.delete(`/api/admin/knowledge/notes/${id}`);
  }
}
