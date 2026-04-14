import { TestBed } from '@angular/core/testing';
import { PLATFORM_ID } from '@angular/core';
import { of } from 'rxjs';
import {
  RibbonService,
  derivePipeline,
  deriveFeeds,
  deriveBudget,
} from './ribbon.service';
import { SystemService } from './system.service';
import type { SystemHealth } from '../models/admin.model';

function fullHealth(overrides: Partial<SystemHealth> = {}): SystemHealth {
  return {
    feeds: {
      total: 25,
      healthy: 25,
      failing: 0,
      failing_feeds: [],
    },
    pipelines: {
      recent_runs: 100,
      failed: 0,
      last_run_at: '2026-04-13T10:00:00Z',
    },
    ai_budget: {
      today_tokens: 1000,
      daily_limit: 10000,
    },
    database: {
      contents_count: 100,
      tasks_count: 50,
      notes_count: 25,
    },
    ...overrides,
  };
}

describe('RibbonService — instantiation', () => {
  function setup(platform: 'browser' | 'server' = 'browser'): RibbonService {
    TestBed.configureTestingModule({
      providers: [
        { provide: PLATFORM_ID, useValue: platform },
        {
          provide: SystemService,
          useValue: { getHealth: vi.fn(() => of(fullHealth())) },
        },
      ],
    });
    return TestBed.inject(RibbonService);
  }

  it('should construct in browser without throwing', () => {
    expect(() => setup('browser')).not.toThrow();
  });

  it('should construct on server without registering listeners', () => {
    expect(() => setup('server')).not.toThrow();
  });
});

describe('derivePipeline', () => {
  it('should mark ok when no failures', () => {
    expect(derivePipeline(fullHealth())).toEqual({
      label: 'pipeline ok',
      status: 'ok',
    });
  });

  it('should mark warn when 1-2 failures', () => {
    const h = fullHealth({
      pipelines: { recent_runs: 100, failed: 1, last_run_at: null },
    });
    expect(derivePipeline(h).status).toBe('warn');
    expect(derivePipeline(h).label).toBe('pipeline 1 failed');
  });

  it('should mark error when ≥3 failures', () => {
    const h = fullHealth({
      pipelines: { recent_runs: 100, failed: 5, last_run_at: null },
    });
    expect(derivePipeline(h).status).toBe('error');
    expect(derivePipeline(h).label).toBe('pipeline 5 failed');
  });
});

describe('deriveFeeds', () => {
  it('should mark ok when 100% healthy', () => {
    expect(deriveFeeds(fullHealth())).toEqual({
      label: 'feeds 100%',
      status: 'ok',
    });
  });

  it('should mark warn when 90-99%', () => {
    const h = fullHealth({
      feeds: { total: 25, healthy: 24, failing: 1, failing_feeds: [] },
    });
    expect(deriveFeeds(h).status).toBe('warn');
    expect(deriveFeeds(h).label).toBe('feeds 96%');
  });

  it('should mark error below 90%', () => {
    const h = fullHealth({
      feeds: { total: 10, healthy: 8, failing: 2, failing_feeds: [] },
    });
    expect(deriveFeeds(h).status).toBe('error');
    expect(deriveFeeds(h).label).toBe('feeds 80%');
  });

  it('should handle zero total without dividing by zero', () => {
    const h = fullHealth({
      feeds: { total: 0, healthy: 0, failing: 0, failing_feeds: [] },
    });
    expect(deriveFeeds(h)).toEqual({ label: 'feeds —', status: 'ok' });
  });
});

describe('deriveBudget', () => {
  it('should mark ok below 70%', () => {
    expect(deriveBudget(fullHealth())).toEqual({
      label: 'ai 10%',
      status: 'ok',
    });
  });

  it('should mark warn at 70-89%', () => {
    const h = fullHealth({
      ai_budget: { today_tokens: 7500, daily_limit: 10000 },
    });
    expect(deriveBudget(h).status).toBe('warn');
    expect(deriveBudget(h).label).toBe('ai 75%');
  });

  it('should mark error at 90% and above', () => {
    const h = fullHealth({
      ai_budget: { today_tokens: 9500, daily_limit: 10000 },
    });
    expect(deriveBudget(h).status).toBe('error');
    expect(deriveBudget(h).label).toBe('ai 95%');
  });

  it('should handle zero daily limit without dividing by zero', () => {
    const h = fullHealth({
      ai_budget: { today_tokens: 0, daily_limit: 0 },
    });
    expect(deriveBudget(h)).toEqual({ label: 'ai —', status: 'ok' });
  });
});
