import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { LearningSummary } from '../models/workbench.model';
import type {
  ConceptKind,
  ConceptProfile,
  ConceptRow,
  DashboardOverview,
  LearningSessionMode,
  LearningSessionRow,
  MasteryStage,
  ObservationConfidence,
  PlanDetail,
  PlanEntryStatus,
  PlanRow,
  SessionDetail,
} from '../models/learning.model';

export interface DashboardQuery {
  view?:
    | 'overview'
    | 'mastery'
    | 'weaknesses'
    | 'retrieval'
    | 'timeline'
    | 'variations';
  domain?: string;
  confidence_filter?: ObservationConfidence | 'all';
}

export interface ConceptsListQuery {
  domain?: string;
  kind?: ConceptKind;
  mastery_stage?: MasteryStage;
  q?: string;
}

export interface SessionsListQuery {
  domain?: string;
  mode?: LearningSessionMode;
  ended?: boolean;
  sort?: 'started_at';
}

export type ReviewRating = 'again' | 'hard' | 'good' | 'easy';

/** Learning-domain reads: summary, dashboard, concepts, sessions, plans, FSRS reviews. */
@Injectable({ providedIn: 'root' })
export class LearningService {
  private readonly api = inject(ApiService);

  /** Powers the LEARNING cell on Today. */
  summary(): Observable<LearningSummary> {
    return this.api.getData<LearningSummary>('/api/admin/learning/summary');
  }

  dashboard(query: DashboardQuery = {}): Observable<DashboardOverview> {
    const params: Record<string, string> = {};
    params['view'] = query.view ?? 'overview';
    if (query.domain) params['domain'] = query.domain;
    if (query.confidence_filter)
      params['confidence_filter'] = query.confidence_filter;
    return this.api.getData<DashboardOverview>(
      '/api/admin/learning/dashboard',
      params,
    );
  }

  concepts(query: ConceptsListQuery = {}): Observable<ConceptRow[]> {
    const params: Record<string, string> = {};
    if (query.domain) params['domain'] = query.domain;
    if (query.kind) params['kind'] = query.kind;
    if (query.mastery_stage) params['mastery_stage'] = query.mastery_stage;
    if (query.q) params['q'] = query.q;
    return this.api.getData<ConceptRow[]>(
      '/api/admin/learning/concepts',
      params,
    );
  }

  concept(
    slug: string,
    confidenceFilter: ObservationConfidence | 'all' = 'high',
  ): Observable<ConceptProfile> {
    return this.api.getData<ConceptProfile>(
      `/api/admin/learning/concepts/${slug}`,
      { confidence_filter: confidenceFilter },
    );
  }

  session(id: string): Observable<SessionDetail> {
    return this.api.getData<SessionDetail>(
      `/api/admin/learning/sessions/${id}`,
    );
  }

  /** Returns 409 when an active session already exists. */
  startSession(
    domain: string,
    mode: LearningSessionMode,
  ): Observable<LearningSessionRow> {
    return this.api.postData<LearningSessionRow>(
      '/api/admin/learning/sessions',
      { domain, mode },
    );
  }

  endSession(id: string, reflectionMd?: string): Observable<SessionDetail> {
    const body = reflectionMd ? { reflection_md: reflectionMd } : {};
    return this.api.postData<SessionDetail>(
      `/api/admin/learning/sessions/${id}/end`,
      body,
    );
  }

  plans(): Observable<PlanRow[]> {
    return this.api.getData<PlanRow[]>('/api/admin/learning/plans');
  }

  plan(id: string): Observable<PlanDetail> {
    return this.api.getData<PlanDetail>(`/api/admin/learning/plans/${id}`);
  }

  /**
   * When `status === 'completed'` the backend expects
   * `completed_by_attempt_id` + `reason` for the audit trail.
   */
  updatePlanEntry(
    planId: string,
    entryId: string,
    body: {
      status: PlanEntryStatus;
      completed_by_attempt_id?: string;
      reason?: string;
    },
  ): Observable<PlanDetail> {
    return this.api.putData<PlanDetail>(
      `/api/admin/learning/plans/${planId}/entries/${entryId}`,
      body,
    );
  }

  sessions(query: SessionsListQuery = {}): Observable<LearningSessionRow[]> {
    const params: Record<string, string> = {};
    if (query.domain) params['domain'] = query.domain;
    if (query.mode) params['mode'] = query.mode;
    if (query.ended !== undefined) params['ended'] = String(query.ended);
    if (query.sort) params['sort'] = query.sort;
    return this.api.getData<LearningSessionRow[]>(
      '/api/admin/learning/sessions',
      params,
    );
  }

  /** Record an FSRS review; response has the new `due` / `retention`. */
  recordReview(
    cardId: string,
    rating: ReviewRating,
    attemptId?: string,
  ): Observable<{ card_id: string; due: string; retention: number }> {
    const body: Record<string, string> = { rating };
    if (attemptId) body['attempt_id'] = attemptId;
    return this.api.postData<{
      card_id: string;
      due: string;
      retention: number;
    }>(`/api/admin/learning/reviews/${cardId}`, body);
  }
}
