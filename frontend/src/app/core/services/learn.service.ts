import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type {
  LearningDashboard,
  LearningPlanSummary,
  LearningPlanDetail,
} from '../models/admin.model';

/** Concept deep analysis — learning history of a single concept */
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

/** Learning service — learning dashboard, practice sessions, concept analysis */
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

  // Learning Plans
  getPlans(): Observable<{ plans: LearningPlanSummary[] }> {
    return this.api.getData<{ plans: LearningPlanSummary[] }>(
      '/api/admin/learn/plans',
    );
  }

  getPlanDetail(id: string): Observable<LearningPlanDetail> {
    return this.api.getData<LearningPlanDetail>(`/api/admin/learn/plans/${id}`);
  }
}
