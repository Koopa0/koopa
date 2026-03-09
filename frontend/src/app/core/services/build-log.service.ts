import { Injectable, signal, computed } from '@angular/core';
import { Observable, of, throwError } from 'rxjs';
import {
  BuildLog,
  BuildLogListItem,
  BuildLogsResponse,
} from '../models/build-log.model';
import { MOCK_BUILD_LOGS } from './mock-build-logs';

const MOCK_DELAY_MS = 600;

@Injectable({
  providedIn: 'root',
})
export class BuildLogService {
  private readonly buildLogs = signal<BuildLog[]>(MOCK_BUILD_LOGS);

  readonly allBuildLogs = this.buildLogs.asReadonly();

  readonly publishedBuildLogs = computed(() =>
    this.buildLogs().filter((bl) => bl.status === 'published'),
  );

  readonly latestBuildLogs = computed(() =>
    this.publishedBuildLogs()
      .sort((a, b) => b.publishedAt.getTime() - a.publishedAt.getTime())
      .slice(0, 5),
  );

  getBuildLogs(page = 1, limit = 10): Observable<BuildLogsResponse> {
    return new Observable((observer) => {
      setTimeout(() => {
        const published = this.publishedBuildLogs().sort(
          (a, b) => b.publishedAt.getTime() - a.publishedAt.getTime(),
        );
        const startIndex = (page - 1) * limit;
        const endIndex = startIndex + limit;
        const items: BuildLogListItem[] = published
          .slice(startIndex, endIndex)
          .map((bl) => ({
            id: bl.id,
            slug: bl.slug,
            projectId: bl.projectId,
            title: bl.title,
            excerpt: bl.excerpt,
            coverImage: bl.coverImage,
            tags: bl.tags,
            publishedAt: bl.publishedAt,
            readingTime: bl.readingTime,
          }));

        observer.next({
          buildLogs: items,
          total: published.length,
          page,
          limit,
          hasNext: endIndex < published.length,
          hasPrevious: page > 1,
        });
        observer.complete();
      }, MOCK_DELAY_MS);
    });
  }

  getBySlug(slug: string): Observable<BuildLog> {
    const buildLog = this.buildLogs().find(
      (bl) => bl.slug === slug && bl.status === 'published',
    );
    if (!buildLog) {
      return throwError(() => new Error('Build log not found'));
    }
    return of(buildLog);
  }

  getByProjectId(projectId: string): BuildLog[] {
    return this.publishedBuildLogs()
      .filter((bl) => bl.projectId === projectId)
      .sort((a, b) => b.publishedAt.getTime() - a.publishedAt.getTime());
  }
}
