import { Injectable, inject } from '@angular/core';
import { Observable, of } from 'rxjs';
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
    // TODO: const params: Record<string, string | number> = {};
    // if (cursor) params['cursor'] = cursor;
    // if (limit) params['limit'] = limit;
    // return this.api.getData<InboxResponse>('/api/admin/inbox', params);
    return of(MOCK_INBOX);
  }

  /** 快速捕捉到 inbox */
  capture(text: string): Observable<InboxItem> {
    // TODO: return this.api.postData<InboxItem>('/api/admin/inbox/capture', { text });
    const now = new Date().toISOString();
    return of({
      id: `inbox-${Date.now()}`,
      text,
      source: 'manual' as const,
      captured_at: now,
      age_hours: 0,
    });
  }

  /** 澄清 inbox item：轉為 task / journal / insight / discard */
  clarify(id: string, decision: ClarifyDecision): Observable<ClarifyResult> {
    // TODO: return this.api.postData<ClarifyResult>(`/api/admin/inbox/${id}/clarify`, decision);
    return of({
      result: 'clarified' as const,
      entity_type: decision.type,
      entity_id: decision.type === 'discard' ? '' : `entity-${Date.now()}`,
    });
  }
}

// ---------------------------------------------------------------------------
// Mock Data — 嚴格對齊 admin.model.ts
// ---------------------------------------------------------------------------

const MOCK_INBOX: InboxResponse = {
  items: [
    {
      id: 'inbox-001',
      text: '研究 pgvector 的 HNSW vs IVFFlat indexing 策略',
      source: 'mcp',
      captured_at: '2026-04-08T09:15:00+08:00',
      age_hours: 2.5,
    },
    {
      id: 'inbox-002',
      text: 'Review the Angular 21 defer block hydration changes',
      source: 'manual',
      captured_at: '2026-04-08T08:42:00+08:00',
      age_hours: 3,
    },
    {
      id: 'inbox-003',
      text: '寫一篇 TIL: Go 1.26 range-over-func 在 production 的實際應用',
      source: 'manual',
      captured_at: '2026-04-07T22:10:00+08:00',
      age_hours: 13.5,
    },
    {
      id: 'inbox-004',
      text: 'Check if NATS JetStream exactly-once is stable for our use case',
      source: 'mcp',
      captured_at: '2026-04-07T16:30:00+08:00',
      age_hours: 19,
    },
    {
      id: 'inbox-005',
      text: 'Catalyst UI Kit 新的 Combobox 元件可以取代目前的 Select',
      source: 'rss',
      captured_at: '2026-04-07T11:05:00+08:00',
      age_hours: 24.5,
    },
  ],
  stats: {
    total: 5,
    oldest_age_days: 1,
    by_source: { manual: 2, mcp: 2, rss: 1 },
  },
};
