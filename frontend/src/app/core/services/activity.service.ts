import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import type {
    ActivityEntityType,
    ChangelogResponse,
} from '../models/activity.model';
import { ApiService } from './api.service';

/**
 * Query for GET /api/admin/system/activity. The backend
 * (internal/activity/handler.go::Changelog) honors `source` (entity type),
 * `project`, `actor` (comma-separated), and `days`. There is no
 * change-kind filter — kind is a display attribute on each event, never a
 * server-side filter.
 */
export interface ChangelogQuery {
  /** Entity type — sent to the backend as `source`. */
  source?: ActivityEntityType;
  project?: string;
  /** filter by agent. Backend may ignore until ChangelogEvent.actor lands. */
  actor?: string;
}

/** Cross-domain activity / audit log. */
@Injectable({ providedIn: 'root' })
export class ActivityService {
  private readonly api = inject(ApiService);

  changelog(query: ChangelogQuery = {}): Observable<ChangelogResponse> {
    const params: Record<string, string> = {};
    if (query.source) params['source'] = query.source;
    if (query.project) params['project'] = query.project;
    if (query.actor) params['actor'] = query.actor;
    return this.api.getData<ChangelogResponse>(
      '/api/admin/system/activity',
      params,
    );
  }
}
