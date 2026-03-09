import { Injectable, signal, computed } from '@angular/core';
import { Observable, of, throwError } from 'rxjs';
import { TilEntry } from '../models/til.model';
import { MOCK_TILS } from './mock-tils';

@Injectable({
  providedIn: 'root',
})
export class TilService {
  private readonly tils = signal<TilEntry[]>(MOCK_TILS);

  readonly allTils = this.tils.asReadonly();

  readonly publishedTils = computed(() =>
    this.tils()
      .filter((t) => t.status === 'published')
      .sort((a, b) => b.publishedAt.getTime() - a.publishedAt.getTime()),
  );

  readonly latestTils = computed(() => this.publishedTils().slice(0, 5));

  getBySlug(slug: string): Observable<TilEntry> {
    const til = this.tils().find(
      (t) => t.slug === slug && t.status === 'published',
    );
    if (!til) {
      return throwError(() => new Error('TIL not found'));
    }
    return of(til);
  }

  getByTag(tag: string): TilEntry[] {
    return this.publishedTils().filter((t) => t.tags.includes(tag));
  }
}
