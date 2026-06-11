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
  Plan,
  PlanDetail,
  PlanEntryDetail,
  PlanEntryStatus,
  PlanStatus,
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

export interface Domain {
  slug: string;
  name: string;
}

export interface DomainCreateRequest {
  slug: string;
  name: string;
}

/**
 * Plan create request. `title` + `domain` are required; `goal_id` links the
 * plan to a commitment goal, and `target_count` seeds the planned entry count.
 * Optional fields are sent only when present so the server applies its defaults.
 */
export interface PlanCreateRequest {
  title: string;
  description: string;
  domain: string;
  goal_id?: string;
  target_count?: number;
}

/** Learning-domain reads: summary, dashboard, concepts, sessions, plans. */
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
    domain: string,
    confidenceFilter: ObservationConfidence | 'all' = 'high',
  ): Observable<ConceptProfile> {
    return this.api.getData<ConceptProfile>(
      `/api/admin/learning/concepts/${slug}`,
      { domain, confidence_filter: confidenceFilter },
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

  /** Draft + active plans only — the management list view. No progress data. */
  plans(): Observable<Plan[]> {
    return this.api.getData<Plan[]>('/api/admin/learning/plans');
  }

  plan(id: string): Observable<PlanDetail> {
    return this.api.getData<PlanDetail>(`/api/admin/learning/plans/${id}`);
  }

  /**
   * Create a learning plan. The server always creates `status=draft`;
   * activation goes through {@link updatePlanStatus}. Returns the created
   * plan so the caller can route to its detail page.
   */
  createPlan(body: PlanCreateRequest): Observable<Plan> {
    return this.api.postData<Plan>('/api/admin/learning/plans', body);
  }

  /** Plan lifecycle transition. Returns the updated plan (no entries). */
  updatePlanStatus(id: string, status: PlanStatus): Observable<Plan> {
    return this.api.putData<Plan>(`/api/admin/learning/plans/${id}/status`, {
      status,
    });
  }

  /**
   * Atomic position rewrite. Send EVERY entry of the plan — untouched
   * entries holding a requested position make the server 409. Returns the
   * full detail envelope reflecting the new order.
   */
  reorderPlanEntries(
    id: string,
    entries: { plan_entry_id: string; position: number }[],
  ): Observable<PlanDetail> {
    return this.api.putData<PlanDetail>(
      `/api/admin/learning/plans/${id}/reorder`,
      { entries },
    );
  }

  /**
   * Entry transition. The audit gate is server-enforced: `completed`
   * REQUIRES `completed_by_attempt_id` + a non-blank `reason`
   * (400 AUDIT_REQUIRED otherwise); `substituted` REQUIRES
   * `substituted_by` (another plan entry id). Returns the bare updated
   * entry — reload the detail envelope for fresh progress counts.
   */
  updatePlanEntry(
    planId: string,
    entryId: string,
    body: {
      status: PlanEntryStatus;
      completed_by_attempt_id?: string;
      reason?: string;
      substituted_by?: string;
    },
  ): Observable<PlanEntryDetail> {
    return this.api.putData<PlanEntryDetail>(
      `/api/admin/learning/plans/${planId}/entries/${entryId}`,
      body,
    );
  }

  /** Draft plans only — the server 409s for any other plan status. */
  removePlanEntry(planId: string, entryId: string): Observable<void> {
    return this.api.delete(
      `/api/admin/learning/plans/${planId}/entries/${entryId}`,
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

  getDomains(): Observable<Domain[]> {
    return this.api.getData<Domain[]>('/api/admin/learning/domains');
  }

  createDomain(body: DomainCreateRequest): Observable<Domain> {
    return this.api.postData<Domain>('/api/admin/learning/domains', body);
  }
}
