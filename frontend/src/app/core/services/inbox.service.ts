import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  InboxResponse,
  InboxItem,
  ClarifyDecision,
  ClarifyResult,
} from '../models/admin.model';

/** 收件匣服務 — 快速捕捉與澄清 */
@Injectable({ providedIn: 'root' })
export class InboxService {
  private readonly api = inject(ApiService);

  /** 取得收件匣項目 */
  getInbox(_cursor?: string, _limit?: number): Observable<InboxResponse> {
    return this.api.getData<InboxResponse>('/api/admin/inbox');
  }

  /** 快速捕捉到 inbox */
  capture(text: string): Observable<InboxItem> {
    return this.api.postData<InboxItem>('/api/admin/inbox/capture', { text });
  }

  /** 澄清 inbox item：轉為 task / journal / insight / discard */
  clarify(id: string, decision: ClarifyDecision): Observable<ClarifyResult> {
    return this.api.postData<ClarifyResult>(
      `/api/admin/inbox/${id}/clarify`,
      decision,
    );
  }
}
