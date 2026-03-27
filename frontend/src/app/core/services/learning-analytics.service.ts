import { inject, Injectable } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiService } from './api.service';

export interface CoverageMatrixTopic {
  topic: string;
  count: number;
  last_date: string;
  results: {
    'ac-independent': number;
    'ac-with-hints': number;
    'ac-after-solution': number;
    'incomplete': number;
  };
}

export interface CoverageMatrixResponse {
  topics: CoverageMatrixTopic[];
  total_entries: number;
  period_days: number;
}

export interface TagSummaryTag {
  tag: string;
  count: number;
}

export interface TagSummaryResponse {
  tags: TagSummaryTag[];
  total_tags: number;
  period_days: number;
}

export interface WeaknessTrendOccurrence {
  date: string;
  result: string;
  title: string;
}

export interface WeaknessTrendResponse {
  tag: string;
  occurrences: WeaknessTrendOccurrence[];
  trend: 'improving' | 'stable' | 'declining' | 'insufficient-data';
  period_days: number;
}

@Injectable({ providedIn: 'root' })
export class LearningAnalyticsService {
  private readonly api = inject(ApiService);

  getCoverageMatrix(project: string, days = 365): Observable<CoverageMatrixResponse> {
    return this.api.getData<CoverageMatrixResponse>('/api/admin/stats/coverage-matrix', { project, days });
  }

  getTagSummary(project: string, tagPrefix = '', days = 90): Observable<TagSummaryResponse> {
    return this.api.getData<TagSummaryResponse>('/api/admin/stats/tag-summary', { project, tag_prefix: tagPrefix, days });
  }

  getWeaknessTrend(project: string, tag: string, days = 30): Observable<WeaknessTrendResponse> {
    return this.api.getData<WeaknessTrendResponse>('/api/admin/stats/weakness-trend', { project, tag, days });
  }
}
