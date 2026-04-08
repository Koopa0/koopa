import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { LearningDashboard } from '../models/admin.model';

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
    return this.api.getData<LearningDashboard>('/api/admin/learn/dashboard');
  }

  startSession(
    domain: string,
    focusConcepts?: string[],
  ): Observable<{ session_id: string }> {
    return this.api.postData<{ session_id: string }>(
      '/api/admin/learn/sessions/start',
      { domain, focus_concepts: focusConcepts },
    );
  }

  endSession(sessionId: string): Observable<void> {
    return this.api.postVoid(`/api/admin/learn/sessions/${sessionId}/end`, {});
  }

  getConceptDrilldown(slug: string): Observable<ConceptDrilldown> {
    return this.api.getData<ConceptDrilldown>(
      `/api/admin/learn/concepts/${slug}`,
    );
  }
}
