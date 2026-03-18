import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { ApiSession, ApiChangelogDay } from '../models';

/** Admin service for activity sessions and changelog */
@Injectable({ providedIn: 'root' })
export class ActivityService {
  private readonly api = inject(ApiService);

  getSessions(days = 7): Observable<ApiSession[]> {
    return this.api.getData<ApiSession[]>('/api/admin/activity/sessions', { days });
  }

  getChangelog(days = 30): Observable<ApiChangelogDay[]> {
    return this.api.getData<ApiChangelogDay[]>('/api/admin/activity/changelog', { days });
  }
}
