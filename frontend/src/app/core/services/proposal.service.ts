import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { concatMap } from 'rxjs/operators';
import { ApiService } from './api.service';

/**
 * A proposed goal awaiting owner triage (goal.ProposedGoalSummary). `area_id`
 * points at a proposed area when this goal is part of a proposed bundle,
 * otherwise it is standalone (null, or under an already-active area).
 * `proposal_rationale` is the agent's why-now justification — absent on older
 * rows proposed before the field existed.
 */
export interface ProposedGoal {
  id: string;
  title: string;
  description: string;
  area_id?: string;
  area_name: string;
  created_by?: string;
  created_at: string;
  milestone_total: number;
  proposal_rationale?: string;
}

/** A proposed PARA area awaiting owner triage (goal.ProposedAreaSummary).
 *  `proposal_rationale` is the agent's why-now justification — absent on older
 *  rows proposed before the field existed. */
export interface ProposedArea {
  id: string;
  slug: string;
  name: string;
  description: string;
  created_by?: string;
  created_at: string;
  proposal_rationale?: string;
}

/** GET /api/admin/commitment/proposals payload. */
export interface ProposalsResponse {
  goals: ProposedGoal[];
  areas: ProposedArea[];
}

const BASE = '/api/admin/commitment';

/**
 * Proposal triage — the human review surface for agent-proposed inert goal
 * and area drafts (MCP propose_goal / propose_area). Reads (list + count)
 * are read-only; activate flips a draft into the live planning lifecycle
 * (goal → not_started, area → active), reject is a hard delete (rejecting an
 * area cascade-deletes its proposed child goals server-side). The owner is
 * the sole decision-maker — agents never call these.
 */
@Injectable({ providedIn: 'root' })
export class ProposalService {
  private readonly api = inject(ApiService);

  /** Every proposed goal and area awaiting review. */
  list(): Observable<ProposalsResponse> {
    return this.api.getData<ProposalsResponse>(`${BASE}/proposals`);
  }

  /** Nav-badge count of proposed goals + areas awaiting triage. */
  count(): Observable<number> {
    return this.api.getData<number>(`${BASE}/proposals/count`);
  }

  /** Activate a standalone proposed goal (proposed → not_started). */
  activateGoal(id: string): Observable<void> {
    return this.api.postVoid(`${BASE}/goals/${id}/activate`, {});
  }

  /** Activate a proposed area (proposed → active). Area-only: its proposed
   *  child goals stay proposed under the now-active area and resurface in
   *  triage as standalone goal cards for individual review. */
  activateArea(id: string): Observable<void> {
    return this.api.postVoid(`${BASE}/areas/${id}/activate`, {});
  }

  /** Edit a proposed goal's title, then activate it (proposed → not_started).
   *  The PUT must complete before the activate, so the two are sequenced with
   *  concatMap rather than run in parallel. */
  editThenActivateGoal(id: string, title: string): Observable<void> {
    return this.api
      .putData<unknown>(`${BASE}/goals/${id}`, { title })
      .pipe(concatMap(() => this.activateGoal(id)));
  }

  /** Reject a standalone proposed goal (hard delete; milestones cascade). */
  rejectGoal(id: string): Observable<void> {
    return this.api.delete(`${BASE}/goals/${id}/proposed`);
  }

  /** Reject a proposed area (hard delete; its proposed child goals cascade
   *  server-side in one transaction). */
  rejectArea(id: string): Observable<void> {
    return this.api.delete(`${BASE}/areas/${id}/proposed`);
  }
}
