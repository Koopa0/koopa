import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { concatMap, map } from 'rxjs/operators';
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

/** A proposed project awaiting owner triage (project.ProposedProjectSummary).
 *  `proposal_rationale` is the agent's why-now justification — absent when none
 *  was given. Surfaced only here in triage, never in the active project list. */
export interface ProposedProject {
  id: string;
  slug: string;
  title: string;
  description: string;
  created_by?: string;
  created_at: string;
  proposal_rationale?: string;
}

/** GET /api/admin/commitment/proposals payload. */
export interface ProposalsResponse {
  goals: ProposedGoal[];
  areas: ProposedArea[];
  projects: ProposedProject[];
}

/** GET /api/admin/commitment/proposals/count payload — the per-entity
 *  breakdown the backend returns. The nav badge wants one number, so the
 *  three are summed in {@link ProposalService.count}. */
export interface ProposalsCount {
  proposed_goals: number;
  proposed_areas: number;
  proposed_projects: number;
}

const BASE = '/api/admin/commitment';

/**
 * Proposal triage — the human review surface for agent-proposed inert goal,
 * area, and project drafts (MCP propose_goal / propose_area / propose_project).
 * Reads (list + count) are read-only; activate flips a draft into the live
 * planning lifecycle (goal → not_started, area → active, project → in_progress),
 * reject is a hard delete (rejecting an area cascade-deletes its proposed child
 * goals server-side). The owner is the sole decision-maker — agents never call
 * these.
 */
@Injectable({ providedIn: 'root' })
export class ProposalService {
  private readonly api = inject(ApiService);

  /** Every proposed goal and area awaiting review. */
  list(): Observable<ProposalsResponse> {
    return this.api.getData<ProposalsResponse>(`${BASE}/proposals`);
  }

  /** Nav-badge total of proposed goals + areas + projects awaiting triage.
   *  The endpoint returns a per-entity breakdown, so the three are summed
   *  into the single number the badge renders. */
  count(): Observable<number> {
    return this.api
      .getData<ProposalsCount>(`${BASE}/proposals/count`)
      .pipe(
        map(
          (c) => c.proposed_goals + c.proposed_areas + c.proposed_projects,
        ),
      );
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

  /** Activate a proposed project (proposed → in_progress). */
  activateProject(id: string): Observable<void> {
    return this.api.postVoid(`${BASE}/projects/${id}/activate`, {});
  }

  /** Reject a proposed project (hard delete). Linked todos and contents
   *  survive unclassified server-side; the project profile cascades. */
  rejectProject(id: string): Observable<void> {
    return this.api.delete(`${BASE}/projects/${id}/proposed`);
  }
}
