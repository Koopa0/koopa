import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { ApiPolishResult } from '../models';

/** Admin service for AI content polish workflow */
@Injectable({ providedIn: 'root' })
export class FlowPolishService {
  private readonly api = inject(ApiService);

  /** Trigger Claude polish for a content item */
  triggerPolish(contentId: string): Observable<void> {
    return this.api.postVoid(`/api/admin/flow/polish/${contentId}`, {});
  }

  /** Get polish result (original vs polished body) */
  getResult(contentId: string): Observable<ApiPolishResult> {
    return this.api.getData<ApiPolishResult>(`/api/admin/flow/polish/${contentId}/result`);
  }

  /** Approve polished content — replaces original body */
  approve(contentId: string): Observable<void> {
    return this.api.postVoid(`/api/admin/flow/polish/${contentId}/approve`, {});
  }
}
