import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';

/** One ヨルシカ track on the shelf. The study fields (lyrics_ja,
 *  translation, vocabulary) are owner-filled and `''` until entered;
 *  `album` is `''` when not recorded. There is no artist column — the
 *  whole shelf is ヨルシカ. No rating, score, or progress field exists. */
export interface Song {
  id: string;
  title_ja: string;
  album: string;
  lyrics_ja: string;
  translation: string;
  vocabulary: string;
  is_public: boolean;
  created_at: string;
  updated_at: string;
}

/** One dated diary entry under a song. `entry_date` is the diary date
 *  (YYYY-MM-DD), not necessarily the typing date. */
export interface SongReflection {
  id: string;
  song_id: string;
  entry_date: string;
  body: string;
  created_at: string;
  updated_at: string;
}

/** Song page payload: the song flat, plus its diary thread ordered
 *  entry_date asc (created_at tiebreak). */
export interface SongDetail extends Song {
  reflections: SongReflection[];
}

/** Create body — only `title_ja` is required; the study fields default
 *  to empty for the owner to fill later. */
export interface CreateSongRequest {
  title_ja: string;
  album?: string;
  lyrics_ja?: string;
  translation?: string;
  vocabulary?: string;
}

/** Partial update — omitted fields stay unchanged. `title_ja` cannot be
 *  blanked through this path (the server rejects it). */
export interface UpdateSongRequest {
  title_ja?: string;
  album?: string;
  lyrics_ja?: string;
  translation?: string;
  vocabulary?: string;
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
 *  the writer's day, not UTC's). Duplicated from the reading shelf rather
 *  than coupling two sibling features through a shared import. */
export function todayISODate(): string {
  const now = new Date();
  return new Date(now.getTime() - now.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 10);
}

const BASE = '/api/admin/knowledge/songs';

/**
 * ヨルシカ song shelf + reflection diary — maps to the 8 admin endpoints
 * under /api/admin/knowledge/songs. This admin surface is the only access
 * path (no MCP tool, not in the search corpus, deeply private by design).
 * No rating field, ever — evaluation happens through reflections.
 */
@Injectable({ providedIn: 'root' })
export class SongService {
  private readonly api = inject(ApiService);

  /** Shelf list, ordered updated_at desc. Album grouping is the
   *  frontend's call. */
  list(): Observable<Song[]> {
    return this.api.getData<Song[]>(BASE);
  }

  /** The song page: song + full reflection thread. */
  detail(id: string): Observable<SongDetail> {
    return this.api.getData<SongDetail>(`${BASE}/${id}`);
  }

  /** Add a song. Only title_ja is required. */
  create(request: CreateSongRequest): Observable<Song> {
    return this.api.postData<Song>(BASE, request);
  }

  update(id: string, request: UpdateSongRequest): Observable<Song> {
    return this.api.putData<Song>(`${BASE}/${id}`, request);
  }

  /** Deletes the song — the diary cascades with it. */
  remove(id: string): Observable<void> {
    return this.api.delete(`${BASE}/${id}`);
  }

  addReflection(
    songId: string,
    request: CreateReflectionRequest,
  ): Observable<SongReflection> {
    return this.api.postData<SongReflection>(
      `${BASE}/${songId}/reflections`,
      request,
    );
  }

  updateReflection(
    songId: string,
    reflectionId: string,
    request: UpdateReflectionRequest,
  ): Observable<SongReflection> {
    return this.api.putData<SongReflection>(
      `${BASE}/${songId}/reflections/${reflectionId}`,
      request,
    );
  }

  removeReflection(songId: string, reflectionId: string): Observable<void> {
    return this.api.delete(`${BASE}/${songId}/reflections/${reflectionId}`);
  }
}
