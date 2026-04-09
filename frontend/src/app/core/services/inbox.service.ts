import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  InboxResponse,
  InboxItem,
  ClarifyDecision,
  ClarifyResult,
} from '../models/admin.model';

/** Inbox service — quick capture and clarify */
@Injectable({ providedIn: 'root' })
export class InboxService {
  private readonly api = inject(ApiService);

  /** Get inbox items */
  getInbox(_cursor?: string, _limit?: number): Observable<InboxResponse> {
    return this.api.getData<InboxResponse>('/api/admin/inbox');
  }

  /** Quick capture to inbox */
  capture(text: string): Observable<InboxItem> {
    return this.api.postData<InboxItem>('/api/admin/inbox/capture', { text });
  }

  /** Clarify inbox item: convert to task / journal / insight / discard */
  clarify(id: string, decision: ClarifyDecision): Observable<ClarifyResult> {
    return this.api.postData<ClarifyResult>(
      `/api/admin/inbox/${id}/clarify`,
      decision,
    );
  }
}
