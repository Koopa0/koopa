import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { ApiSessionNote } from '../models';

/** Admin service for session notes */
@Injectable({ providedIn: 'root' })
export class SessionNoteService {
  private readonly api = inject(ApiService);

  list(date?: string, type?: string, days?: number): Observable<ApiSessionNote[]> {
    const params = new URLSearchParams();
    if (date) params.set('date', date);
    if (type) params.set('type', type);
    if (days) params.set('days', String(days));
    const qs = params.toString();
    const url = '/api/admin/session-notes' + (qs ? '?' + qs : '');
    return this.api.getData<ApiSessionNote[]>(url);
  }
}
