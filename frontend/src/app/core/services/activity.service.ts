import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import type {
    ActivityChangeKind,
    ActivityEntityType,
    ChangelogResponse,
} from '../models/activity.model';
import { ApiService } from './api.service';

export interface ChangelogQuery {
  entity_type?: ActivityEntityType;
  change_kind?: ActivityChangeKind;
  since?: string;
  until?: string;
  /** filter by agent. Backend may ignore until ChangelogEvent.actor lands. */
  actor?: string;
}

/** Cross-domain activity / audit log. */
@Injectable({ providedIn: 'root' })
export class ActivityService {
  private readonly api = inject(ApiService);

  changelog(query: ChangelogQuery = {}): Observable<ChangelogResponse> {
    const params: Record<string, string> = {};
    if (query.entity_type) params['entity_type'] = query.entity_type;
    if (query.change_kind) params['change_kind'] = query.change_kind;
    if (query.since) params['since'] = query.since;
    if (query.until) params['until'] = query.until;
    if (query.actor) params['actor'] = query.actor;
    return this.api.getData<ChangelogResponse>(
      '/api/admin/coordination/activity',
      params,
    );
  }
}
