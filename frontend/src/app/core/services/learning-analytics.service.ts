import { inject, Injectable } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';

// ─── Coverage Matrix (existing) ───

export interface CoverageMatrixTopic {
  topic: string;
  count: number;
  last_date: string;
  results: {
    'ac-independent': number;
    'ac-with-hints': number;
    'ac-after-solution': number;
    incomplete: number;
  };
}

export interface CoverageMatrixResponse {
  topics: CoverageMatrixTopic[];
  total_entries: number;
  period_days: number;
}

// ─── Tag Summary (existing) ───

export interface TagSummaryTag {
  tag: string;
  count: number;
}

export interface TagSummaryResponse {
  tags: TagSummaryTag[];
  total_tags: number;
  period_days: number;
}

// ─── Weakness Trend (updated: Checkpoint 1 adds slug + observation) ───

export interface WeaknessTrendOccurrence {
  date: string;
  result: string;
  title: string;
  slug: string;
  observation: string;
}

export interface WeaknessTrendResponse {
  tag: string;
  occurrences: WeaknessTrendOccurrence[];
  trend: 'improving' | 'stable' | 'declining' | 'insufficient-data';
  period_days: number;
}

// ─── Learning Timeline (new: Checkpoint 2) ───

export interface TimelineEntry {
  slug: string;
  title: string;
  project: string;
  content_type: string;
  result?: string;
  tags: string[];
  learning_type?: string;
  weakness_observations?: WeaknessObservation[];
  key_concepts?: KeyConcept[];
}

export interface WeaknessObservation {
  tag: string;
  observation: string;
  status: string;
}

export interface KeyConcept {
  name: string;
  understanding: 'clear' | 'fuzzy' | 'not-understood';
  connection?: string;
  retrieval_target?: boolean;
}

export interface TimelineDay {
  date: string;
  entries: TimelineEntry[];
}

export interface TimelineSummary {
  total_entries: number;
  active_days: number;
  current_streak: number;
  by_project: Record<string, number>;
}

export interface LearningTimelineResult {
  days: TimelineDay[];
  summary: TimelineSummary;
}

// ─── Retrieval Attempt (new: Checkpoint 2) ───

export type RetrievalQuality = 'easy' | 'hard' | 'failed';

export interface RetrievalAttemptResult {
  attempt_id: number;
  next_due: string;
  interval_days: number;
  ease_factor: number;
}

@Injectable({ providedIn: 'root' })
export class LearningAnalyticsService {
  private readonly api = inject(ApiService);

  // ─── Existing endpoints ───

  getCoverageMatrix(
    project: string,
    days = 365,
  ): Observable<CoverageMatrixResponse> {
    return this.api.getData<CoverageMatrixResponse>(
      '/api/admin/stats/coverage-matrix',
      { project, days },
    );
  }

  getTagSummary(
    project: string,
    tagPrefix = '',
    days = 90,
  ): Observable<TagSummaryResponse> {
    return this.api.getData<TagSummaryResponse>(
      '/api/admin/stats/tag-summary',
      { project, tag_prefix: tagPrefix, days },
    );
  }

  getWeaknessTrend(
    project: string,
    tag: string,
    days = 30,
  ): Observable<WeaknessTrendResponse> {
    return this.api.getData<WeaknessTrendResponse>(
      '/api/admin/stats/weakness-trend',
      { project, tag, days },
    );
  }

  // ─── New endpoints (Checkpoint 2) ───

  getLearningTimeline(
    project?: string,
    days = 14,
  ): Observable<LearningTimelineResult> {
    const params: Record<string, string | number> = { days };
    if (project) {
      params['project'] = project;
    }
    return this.api.getData<LearningTimelineResult>(
      '/api/admin/stats/learning-timeline',
      params,
    );
  }

  logRetrievalAttempt(
    contentSlug: string,
    quality: RetrievalQuality,
    tag?: string,
  ): Observable<RetrievalAttemptResult> {
    const body: Record<string, string> = { content_slug: contentSlug, quality };
    if (tag) {
      body['tag'] = tag;
    }
    return this.api.postData<RetrievalAttemptResult>(
      '/api/admin/retrieval-attempts',
      body,
    );
  }
}
