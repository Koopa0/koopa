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

  addEvidence(id: string, body: AddEvidenceRequest): Observable<Hypothesis> {
    return this.api.postData<Hypothesis>(
      `/api/admin/learning/hypotheses/${id}/evidence`,
      body,
    );
  }
}
