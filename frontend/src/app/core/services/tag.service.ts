import { Injectable, signal, computed } from '@angular/core';
import { Observable, of, delay } from 'rxjs';
import { Tag, TagCloud } from '../models';
import { MOCK_TAGS, MOCK_ARTICLES } from './mock-data';
import { MOCK_BUILD_LOGS } from './mock-build-logs';
import { MOCK_TILS } from './mock-tils';
import { MOCK_NOTES } from './mock-notes';

/** 根據所有內容類型計算每個標籤的內容數 */
function buildTagsWithCounts(): Tag[] {
  const countMap = new Map<string, number>();
  const allTagSources = [
    ...MOCK_ARTICLES.map((a) => a.tags),
    ...MOCK_BUILD_LOGS.map((bl) => bl.tags),
    ...MOCK_TILS.map((t) => t.tags),
    ...MOCK_NOTES.map((n) => n.tags),
  ];
  for (const tags of allTagSources) {
    for (const tagName of tags) {
      countMap.set(tagName, (countMap.get(tagName) ?? 0) + 1);
    }
  }
  return MOCK_TAGS.map((tag) => ({
    ...tag,
    articleCount: countMap.get(tag.name) ?? 0,
  }));
}

const COMPUTED_TAGS = buildTagsWithCounts();

@Injectable({
  providedIn: 'root',
})
export class TagService {
  private readonly _tags = signal<Tag[]>(COMPUTED_TAGS);
  private readonly _isLoading = signal(false);
  private readonly _error = signal<string | null>(null);

  readonly tagList = this._tags.asReadonly();
  readonly loading = this._isLoading.asReadonly();
  readonly errorMessage = this._error.asReadonly();

  readonly popularTags = computed(() =>
    this._tags()
      .filter((tag) => tag.articleCount > 0)
      .sort((a, b) => b.articleCount - a.articleCount)
      .slice(0, 10),
  );

  readonly tagCloud = computed((): TagCloud[] => {
    const tags = this._tags().filter((tag) => tag.articleCount > 0);
    const maxCount = Math.max(...tags.map((tag) => tag.articleCount), 1);

    return tags.map((tag) => ({
      tag,
      weight: Math.round((tag.articleCount / maxCount) * 5) + 1,
    }));
  });

  getAllTags(): Observable<Tag[]> {
    this._isLoading.set(true);
    this._error.set(null);

    this._isLoading.set(false);
    return of(COMPUTED_TAGS).pipe(delay(300));
  }

  getTagBySlug(slug: string): Observable<Tag | null> {
    this._isLoading.set(true);
    this._error.set(null);

    const tag = COMPUTED_TAGS.find((t) => t.slug === slug) ?? null;
    this._isLoading.set(false);

    return of(tag).pipe(delay(200));
  }

  searchTags(query: string): Observable<Tag[]> {
    this._isLoading.set(true);
    this._error.set(null);

    const filteredTags = COMPUTED_TAGS.filter(
      (tag) =>
        tag.name.toLowerCase().includes(query.toLowerCase()) ||
        tag.description?.toLowerCase().includes(query.toLowerCase()),
    );

    this._isLoading.set(false);
    return of(filteredTags).pipe(delay(300));
  }
}
