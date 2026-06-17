import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';
import type { Hypothesis } from '../models/workbench.model';

/** Hypothesis lineage envelope — origin session + attempts + observations + evidence log. */
export interface HypothesisLineage {
  hypothesis: Hypothesis;
  origin?: {
    session?: {
      id: string;
      domain: string;
      mode: string;
      started_at: string;
      ended_at: string | null;
    };
    attempts: LineageAttempt[];
  };
  observations: LineageObservation[];
  evidence_log: LineageEvidence[];
}

export interface LineageAttempt {
  id: string;
  target_title: string;
  outcome: string;
  attempted_at: string;
  duration_minutes?: number | null;
}

export interface LineageObservation {
  id: string;
  signal_type: 'weakness' | 'improvement' | 'mastery';
  category: string;
  severity?: 'critical' | 'moderate' | 'minor' | null;
  detail: string;
  concept_slug?: string | null;
  concept_name?: string | null;
}

export interface LineageEvidence {
  id: string;
  type: 'supporting' | 'counter';
  body: string;
  linked_attempt_id: string | null;
  linked_observation_id: string | null;
  added_at: string;
  actor: string;
}

/** Body for `POST /api/admin/learning/hypotheses/:id/evidence`. */
export interface AddEvidenceRequest {
  type: 'supporting' | 'counter';
  body: string;
  linked_attempt_id?: string;
  linked_observation_id?: string;
}

/**
 * Body for `POST /api/admin/learning/hypotheses`. Lands `state=unverified`;
 * `created_by` comes from the session actor. `observed_date` is a YYYY-MM-DD
 * calendar date (date-only per the contract, not RFC3339).
 */
export interface HypothesisCreateRequest {
  claim: string;
  invalidation_condition: string;
  content?: string;
  observed_date?: string;
}

@Injectable({ providedIn: 'root' })
export class HypothesisService {
  private readonly api = inject(ApiService);

  list(state?: string): Observable<Hypothesis[]> {
    const params: Record<string, string> = {};
    if (state) params['state'] = state;
    return this.api.getData<Hypothesis[]>(
      '/api/admin/learning/hypotheses',
      params,
    );
  }

  get(id: string): Observable<Hypothesis> {
    return this.api.getData<Hypothesis>(`/api/admin/learning/hypotheses/${id}`);
  }

  /**
   * Create a hypothesis (human-only, adminMid). Lands `state=unverified`;
   * returns the created record so the caller can route to its profile.
   */
  create(body: HypothesisCreateRequest): Observable<Hypothesis> {
    return this.api.postData<Hypothesis>(
      '/api/admin/learning/hypotheses',
      body,
    );
  }

  /** Full profile envelope: origin, attempts, observations, evidence log. */
  lineage(id: string): Observable<HypothesisLineage> {
    return this.api.getData<HypothesisLineage>(
      `/api/admin/learning/hypotheses/${id}/lineage`,
    );
  }

  verify(id: string): Observable<Hypothesis> {
    return this.api.postData<Hypothesis>(
      `/api/admin/learning/hypotheses/${id}/verify`,
      {},
    );
  }

  invalidate(id: string): Observable<Hypothesis> {
    return this.api.postData<Hypothesis>(
      `/api/admin/learning/hypotheses/${id}/invalidate`,
      {},
    );
  }

  archive(id: string): Observable<Hypothesis> {
    return this.api.postData<Hypothesis>(
      `/api/admin/learning/hypotheses/${id}/archive`,
      {},
    );
  }

  /**
   * Endorse an agent-drafted hypothesis (draft → unverified) — the owner's
   * decision-stamp under the MCP v3.1 inert-drafts contract. Returns the
   * promoted record. Backend returns 409 NOT_DRAFT on a non-draft row.
   */
  endorse(id: string): Observable<Hypothesis> {
    return this.api.postData<Hypothesis>(
      `/api/admin/learning/hypotheses/${id}/endorse`,
      {},
    );
  }

  /**
   * Delete a draft hypothesis. Draft-only: the backend returns 409 NOT_DRAFT
   * for any other state. Resolves with no body (204).
   */
  deleteDraft(id: string): Observable<void> {
    return this.api.delete(`/api/admin/learning/hypotheses/${id}`);
  }

  addEvidence(id: string, body: AddEvidenceRequest): Observable<Hypothesis> {
    // The handler decodes `{ evidence: {...} }` and 400s when the wrapper is
    // absent (handler.go AddEvidence). The evidence object is stored as-is and
    // read back via the lineage `evidence_log`, so its fields must match.
    return this.api.postData<Hypothesis>(
      `/api/admin/learning/hypotheses/${id}/evidence`,
      { evidence: body },
    );
  }
}
