import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

/** The four shelf states. Transitions are free — abandoned is a
 *  legitimate resting place, not a failure mode. */
export type ReadingStatus =
  | 'want_to_read'
  | 'reading'
  | 'finished'
  | 'abandoned';

/** One book on the shelf. DATE fields are YYYY-MM-DD strings, null when
 *  not recorded. `author` is `''` when not recorded. */
export interface Reading {
  id: string;
  title: string;
  author: string;
  status: ReadingStatus;
  started_on: string | null;
  finished_on: string | null;
  is_public: boolean;
  created_at: string;
  updated_at: string;
}

/** One dated diary entry under a reading. `entry_date` is the diary
 *  date (YYYY-MM-DD), not necessarily the typing date. */
export interface ReadingReflection {
  id: string;
  reading_id: string;
  entry_date: string;
  body: string;
  created_at: string;
  updated_at: string;
}

/** Book page payload: the reading flat, plus its diary thread ordered
 *  entry_date asc (created_at tiebreak). */
export interface ReadingDetail extends Reading {
  reflections: ReadingReflection[];
}

/** `finished_on` is deliberately absent — a finish date is recorded via
 *  update, where the finished auto-stamp rule lives server-side. */
export interface CreateReadingRequest {
  title: string;
  author?: string;
  status?: ReadingStatus;
  started_on?: string;
}

/** Partial update — omitted fields stay unchanged. A recorded date
 *  cannot be cleared back to null through this path. Transitioning to
 *  `finished` without a `finished_on` stamps today server-side. */
export interface UpdateReadingRequest {
  title?: string;
  author?: string;
  status?: ReadingStatus;
  started_on?: string;
  finished_on?: string;
  is_public?: boolean;
}

export interface CreateReflectionRequest {
  body: string;
  /** Defaults to today server-side when omitted. */
  entry_date?: string;
}

export interface UpdateReflectionRequest {
  body?: string;
  entry_date?: string;
}

/** Today as a local-timezone YYYY-MM-DD string (the diary is written in
 *  the writer's day, not UTC's). */
export function todayISODate(): string {
  const now = new Date();
  return new Date(now.getTime() - now.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 10);
}

const BASE = '/api/admin/knowledge/readings';

/**
 * Literature shelf + reading diary — maps to the 8 admin endpoints under
 * /api/admin/knowledge/readings. This admin surface is the only access
 * path (no MCP tool, not in the search corpus). No rating field, ever.
 */
@Injectable({ providedIn: 'root' })
export class ReadingService {
  private readonly api = inject(ApiService);

  /** Shelf list, ordered updated_at desc. Status-group ordering is the
   *  frontend's call. */
  list(status?: ReadingStatus): Observable<Reading[]> {
    return this.api.getData<Reading[]>(BASE, status ? { status } : undefined);
  }

  /** The book page: reading + full reflection thread. */
  detail(id: string): Observable<ReadingDetail> {
    return this.api.getData<ReadingDetail>(`${BASE}/${id}`);
  }

  /** Add a book. Status defaults to want_to_read server-side. */
  create(request: CreateReadingRequest): Observable<Reading> {
    return this.api.postData<Reading>(BASE, request);
  }

  update(id: string, request: UpdateReadingRequest): Observable<Reading> {
    return this.api.putData<Reading>(`${BASE}/${id}`, request);
  }

  /** Deletes the book — the diary cascades with it. */
  remove(id: string): Observable<void> {
    return this.api.delete(`${BASE}/${id}`);
  }

  addReflection(
    readingId: string,
    request: CreateReflectionRequest,
  ): Observable<ReadingReflection> {
    return this.api.postData<ReadingReflection>(
      `${BASE}/${readingId}/reflections`,
      request,
    );
  }

  updateReflection(
    readingId: string,
    reflectionId: string,
    request: UpdateReflectionRequest,
  ): Observable<ReadingReflection> {
    return this.api.putData<ReadingReflection>(
      `${BASE}/${readingId}/reflections/${reflectionId}`,
      request,
    );
  }

  removeReflection(readingId: string, reflectionId: string): Observable<void> {
    return this.api.delete(`${BASE}/${readingId}/reflections/${reflectionId}`);
  }
}
