import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { StudioOverview } from '../models/admin.model';

/** Studio 協調服務 — IPC 指令、報告、參與者 */
@Injectable({ providedIn: 'root' })
export class StudioService {
  private readonly api = inject(ApiService);

  getOverview(): Observable<StudioOverview> {
    return this.api.getData<StudioOverview>('/api/admin/studio/overview');
  }
}
