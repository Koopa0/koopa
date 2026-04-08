import { Injectable, inject } from '@angular/core';
import { Observable, of } from 'rxjs';
import { ApiService } from './api.service';
import type {
  LearningDashboard,
  SessionSummary,
  ConceptWeakness,
  DomainMastery,
} from '../models/admin.model';

/** 概念深入分析 — 單一概念的學習歷程 */
export interface ConceptDrilldown {
  slug: string;
  name: string;
  domain: string;
  kind: string;
  total_attempts: number;
  success_rate: number;
  recent_attempts: ConceptAttempt[];
  related_concepts: RelatedConcept[];
  observations: ConceptObservation[];
}

export interface ConceptAttempt {
  id: string;
  session_id: string;
  outcome: string;
  time_spent_seconds: number;
  attempted_at: string;
}

export interface RelatedConcept {
  slug: string;
  name: string;
  relation: string;
}

export interface ConceptObservation {
  signal: string;
  category: string;
  note: string | null;
  observed_at: string;
}

/** 學習服務 — 學習儀表板、練習 session、概念分析 */
@Injectable({ providedIn: 'root' })
export class LearnService {
  private readonly api = inject(ApiService);

  getDashboard(): Observable<LearningDashboard> {
    // TODO: return this.api.getData<LearningDashboard>('/api/admin/learn/dashboard');
    return of(MOCK_DASHBOARD);
  }

  startSession(
    _domain: string,
    _focusConcepts?: string[],
  ): Observable<{ session_id: string }> {
    // TODO: return this.api.postData<{ session_id: string }>('/api/admin/learn/sessions', { domain, focus_concepts: focusConcepts });
    return of({ session_id: `session-${Date.now()}` });
  }

  endSession(_sessionId: string): Observable<void> {
    // TODO: return this.api.postVoid(`/api/admin/learn/sessions/${sessionId}/end`, {});
    return of(undefined);
  }

  getConceptDrilldown(slug: string): Observable<ConceptDrilldown> {
    // TODO: return this.api.getData<ConceptDrilldown>(`/api/admin/learn/concepts/${slug}`);
    return of({
      ...MOCK_CONCEPT_DRILLDOWN,
      slug,
    });
  }
}

// ---------------------------------------------------------------------------
// Mock Data — 欄位嚴格對齊 admin.model.ts
// ---------------------------------------------------------------------------

const MOCK_RECENT_SESSIONS: SessionSummary[] = [
  {
    id: 'sess-001',
    domain: 'algorithms',
    started_at: '2026-04-08T09:00:00+08:00',
    duration_minutes: 45,
    attempts_count: 6,
    solved_count: 4,
  },
  {
    id: 'sess-002',
    domain: 'system-design',
    started_at: '2026-04-07T14:30:00+08:00',
    duration_minutes: 60,
    attempts_count: 3,
    solved_count: 2,
  },
  {
    id: 'sess-003',
    domain: 'go-patterns',
    started_at: '2026-04-06T20:00:00+08:00',
    duration_minutes: 30,
    attempts_count: 4,
    solved_count: 4,
  },
];

const MOCK_WEAKNESSES: ConceptWeakness[] = [
  {
    concept_slug: 'dynamic-programming',
    concept_name: 'Dynamic Programming',
    domain: 'algorithms',
    fail_count_30d: 5,
    last_practiced: '2026-04-05T10:00:00+08:00',
    days_since_practice: 3,
  },
  {
    concept_slug: 'graph-bfs',
    concept_name: 'BFS / Level-order Traversal',
    domain: 'algorithms',
    fail_count_30d: 3,
    last_practiced: '2026-04-02T14:00:00+08:00',
    days_since_practice: 6,
  },
  {
    concept_slug: 'consistent-hashing',
    concept_name: 'Consistent Hashing',
    domain: 'system-design',
    fail_count_30d: 2,
    last_practiced: '2026-03-28T09:00:00+08:00',
    days_since_practice: 11,
  },
];

const MOCK_DOMAIN_MASTERY: DomainMastery[] = [
  {
    domain: 'algorithms',
    concepts_total: 42,
    concepts_mastered: 18,
    concepts_weak: 8,
    concepts_untested: 16,
  },
  {
    domain: 'system-design',
    concepts_total: 25,
    concepts_mastered: 7,
    concepts_weak: 5,
    concepts_untested: 13,
  },
];

const MOCK_DASHBOARD: LearningDashboard = {
  due_reviews_count: 12,
  due_reviews_today: 5,
  recent_sessions: MOCK_RECENT_SESSIONS,
  weakness_spotlight: MOCK_WEAKNESSES,
  mastery_by_domain: MOCK_DOMAIN_MASTERY,
  streak: {
    current_days: 7,
    longest: 14,
  },
};

const MOCK_CONCEPT_DRILLDOWN: ConceptDrilldown = {
  slug: 'dynamic-programming',
  name: 'Dynamic Programming',
  domain: 'algorithms',
  kind: 'pattern',
  total_attempts: 18,
  success_rate: 0.56,
  recent_attempts: [
    {
      id: 'att-001',
      session_id: 'sess-001',
      outcome: 'solved_with_hint',
      time_spent_seconds: 1200,
      attempted_at: '2026-04-08T09:15:00+08:00',
    },
    {
      id: 'att-002',
      session_id: 'sess-001',
      outcome: 'gave_up',
      time_spent_seconds: 1800,
      attempted_at: '2026-04-08T09:35:00+08:00',
    },
  ],
  related_concepts: [
    { slug: 'memoization', name: 'Memoization', relation: 'prerequisite' },
    { slug: 'greedy', name: 'Greedy Algorithms', relation: 'sibling' },
  ],
  observations: [
    {
      signal: 'weakness',
      category: 'state-transition',
      note: '難以定義 DP 狀態轉移方程',
      observed_at: '2026-04-08T09:40:00+08:00',
    },
  ],
};
