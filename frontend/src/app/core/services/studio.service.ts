import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { StudioOverview } from '../models/admin.model';

/** Studio coordination service — IPC directives, reports, participants */
@Injectable({ providedIn: 'root' })
export class StudioService {
  private readonly api = inject(ApiService);

  getOverview(): Observable<StudioOverview> {
    return this.api.getData<StudioOverview>('/api/admin/studio/overview');
  }
}
