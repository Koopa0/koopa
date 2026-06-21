import { TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { SystemService } from './system.service';
import type {
  DriftReport,
  StatsLearning,
  StatsOverview,
  SystemHealth,
} from '../models/admin.model';

const mockHealth: SystemHealth = {
  feeds: {
    total: 14,
    healthy: 12,
    failing: 2,
    failing_feeds: [
      { name: 'Go Blog', error: 'dial tcp: timeout', since: '2026-06-09T08:00:00Z' },
      { name: 'HN Daily', error: 'http 503' },
    ],
  },
  pipelines: { recent_runs: 226, failed: 0, last_run_at: '2026-06-10T06:00:00Z' },
  database: {
    contents_count: 120,
    todos_count: 45,
    notes_count: 84,
  },
};

const mockStats: StatsOverview = {
  contents: {
    total: 120,
    by_status: { draft: 20, published: 90, review: 10 },
    by_type: { article: 40, til: 80 },
    published: 90,
  },
  collected: { total: 800, by_status: { pending: 100, curated: 700 } },
  feeds: { total: 14, enabled: 12 },
  process_runs: {
    crawl: { total: 226, by_status: { completed: 220, failed: 6 } },
  },
  projects: { total: 11, by_status: { active: 6 } },
  notes: { total: 84, by_type: { 'concept-note': 50 } },
  activity: { total: 4000, last_24h: 12, last_7d: 90, by_source: { human: 60 } },
  tags: { canonical: 30, aliases: 12, unconfirmed: 4 },
};

const mockDrift: DriftReport = {
  period: '30d',
  areas: [
    {
      area: 'engineering',
      active_goals: 2,
      event_count: 50,
      event_percent: 62.5,
      goal_percent: 40,
      drift_percent: 22.5,
    },
  ],
};

const mockLearning: StatsLearning = {
  notes: { total: 84, last_week: 4, last_month: 12, by_type: { 'solve-note': 8 } },
  activity: { this_week: 9, last_week: 6, trend: 'up' },
  top_tags: [{ name: 'go', count: 21 }],
};

describe('SystemService', () => {
  let service: SystemService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(SystemService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should fetch the system health snapshot', () => {
    service.getHealth().subscribe((res) => {
      expect(res.feeds.failing).toBe(2);
      expect(res.feeds.failing_feeds[1].since).toBeUndefined();
      expect(res.database.notes_count).toBe(84);
    });

    const req = httpMock.expectOne((r) =>
      r.url.endsWith('/api/admin/system/health'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: mockHealth });
  });

  it('should fetch the stats overview', () => {
    service.getStats().subscribe((res) => {
      expect(res.contents.published).toBe(90);
      expect(res.process_runs['crawl'].total).toBe(226);
    });

    const req = httpMock.expectOne((r) =>
      r.url.endsWith('/api/admin/system/stats'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: mockStats });
  });

  it('should fetch the drift report without params by default', () => {
    service.getDrift().subscribe((res) => {
      expect(res.period).toBe('30d');
      expect(res.areas[0].drift_percent).toBeCloseTo(22.5);
    });

    const req = httpMock.expectOne((r) =>
      r.url.endsWith('/api/admin/system/stats/drift'),
    );
    expect(req.request.method).toBe('GET');
    expect(req.request.params.keys()).toHaveLength(0);
    req.flush({ data: mockDrift });
  });

  it('should pass the days param to the drift report when provided', () => {
    service.getDrift(7).subscribe();

    const req = httpMock.expectOne(
      (r) => r.url.endsWith('/api/admin/system/stats/drift'),
    );
    expect(req.request.params.get('days')).toBe('7');
    req.flush({ data: mockDrift });
  });

  it('should fetch learning stats', () => {
    service.getLearningStats().subscribe((res) => {
      expect(res.activity.trend).toBe('up');
      expect(res.top_tags[0].name).toBe('go');
    });

    const req = httpMock.expectOne((r) =>
      r.url.endsWith('/api/admin/system/stats/learning'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: mockLearning });
  });
});
