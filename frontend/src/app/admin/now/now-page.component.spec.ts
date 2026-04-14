import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { NowPageComponent } from './now-page.component';
import type {
  DashboardTrends,
  MyDayContext,
} from '../../core/models/admin.model';

const MOCK_CONTEXT: MyDayContext = {
  date: '2026-04-14',
  context_line: 'Phase 1 day 8 build',
  yesterday_unfinished: [],
  today_plan: [
    {
      id: 'pi1',
      task_id: 't1',
      title: 'write now-page tests',
      area: 'frontend',
      energy: 'high',
      estimated_minutes: 30,
      position: 1,
      status: 'planned',
      planned_date: '2026-04-14',
    },
    {
      id: 'pi2',
      task_id: 't2',
      title: 'commit day 8',
      area: 'frontend',
      energy: 'low',
      estimated_minutes: 5,
      position: 2,
      status: 'planned',
      planned_date: '2026-04-14',
    },
  ],
  overdue_tasks: [],
  needs_attention: {
    inbox_count: 2,
    pending_directives: 0,
    unread_reports: 0,
    due_reviews: 1,
    overdue_tasks: 0,
    stale_someday_count: 0,
  },
  goal_pulse: [
    {
      id: 'g1',
      title: 'admin v2 ship',
      area: 'frontend',
      deadline: '2026-04-30',
      days_remaining: 16,
      milestones_total: 4,
      milestones_done: 2,
      next_milestone: 'NOW page real impl',
      status: 'in-progress',
    },
  ],
  reflection_context: null,
};

const MOCK_TRENDS: DashboardTrends = {
  period: 'week',
  execution: {
    tasks_completed_this_week: 12,
    tasks_completed_last_week: 8,
    trend: 'up',
  },
  plan_adherence: {
    completion_rate_this_week: 85,
    completion_rate_last_week: 70,
  },
  goal_health: { on_track: 2, at_risk: 1, stalled: 0 },
  learning: {
    sessions_this_week: 3,
    weakness_count: 4,
    weakness_change: -1,
    mastery_count: 12,
    mastery_change: 2,
    review_backlog: 7,
  },
  content: {
    published_this_month: 3,
    published_target: 5,
    drafts_in_progress: 2,
  },
  inbox_health: {
    current_count: 2,
    week_start_count: 5,
    clarified_this_week: 3,
    captured_this_week: 1,
  },
  someday_health: { total: 8, stale_count: 1 },
  directive_health: { open_count: 0, avg_resolution_days: 0 },
};

describe('NowPageComponent', () => {
  let fixture: ComponentFixture<NowPageComponent>;
  let httpMock: HttpTestingController;

  function setupAndLoad(): void {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        provideNoopAnimations(),
      ],
    });
    fixture = TestBed.createComponent(NowPageComponent);
    httpMock = TestBed.inject(HttpTestingController);
    fixture.detectChanges();

    httpMock.expectOne('/bff/api/admin/today').flush(MOCK_CONTEXT);
    httpMock.expectOne('/bff/api/admin/dashboard/trends').flush(MOCK_TRENDS);

    fixture.detectChanges();
  }

  it('should render all three columns when data has loaded', () => {
    setupAndLoad();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid="now-attention"]')).toBeTruthy();
    expect(el.querySelector('[data-testid="now-stream"]')).toBeTruthy();
    expect(el.querySelector('[data-testid="now-ambient"]')).toBeTruthy();
    httpMock.verify();
  });

  it('should render today plan items with title and area', () => {
    setupAndLoad();
    const stream = fixture.nativeElement.querySelector(
      '[data-testid="now-stream"]',
    ) as HTMLElement;
    expect(stream.textContent).toContain('write now-page tests');
    expect(stream.textContent).toContain('commit day 8');
    httpMock.verify();
  });

  it('should render goal pulse cards as inspector-targeted links', () => {
    setupAndLoad();
    const cards = fixture.nativeElement.querySelectorAll(
      '[data-testid="goal-pulse-card"]',
    ) as NodeListOf<HTMLAnchorElement>;
    expect(cards.length).toBe(1);
    expect(cards[0].textContent).toContain('admin v2 ship');
    httpMock.verify();
  });

  it('should render attention counts', () => {
    setupAndLoad();
    const attention = fixture.nativeElement.querySelector(
      '[data-testid="now-attention"]',
    ) as HTMLElement;
    expect(attention.textContent).toContain('Inbox');
    expect(attention.textContent).toContain('2');
    expect(attention.textContent).toContain('Due reviews');
    httpMock.verify();
  });

  it('should render trends in ambient column', () => {
    setupAndLoad();
    const ambient = fixture.nativeElement.querySelector(
      '[data-testid="now-ambient"]',
    ) as HTMLElement;
    expect(ambient.textContent).toContain('Execution');
    expect(ambient.textContent).toContain('12');
    expect(ambient.textContent).toContain('Plan adherence');
    expect(ambient.textContent).toContain('85%');
    httpMock.verify();
  });
});
