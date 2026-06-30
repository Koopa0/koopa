import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { TodayPageComponent } from './today-page.component';
import type { TodayBrief } from './today.service';
import { NotificationService } from '../../../core/services/notification.service';
import { CommandPaletteService } from '../../../shared/command-palette/command-palette.service';

// Pins the Today render against the brief(morning) contract
// (GET /api/admin/commitment/today): every section binds the wire field
// names and advance clicks drive the todo state machine over HTTP.

const TODAY_URL = '/api/admin/commitment/today';
const COUNT_URL = '/api/admin/commitment/proposals/count';
const ADVANCE_URL = (id: string) =>
  `/api/admin/commitment/todos/${id}/advance`;

function populatedBrief(): TodayBrief {
  return {
    date: '2026-06-07',
    overdue_todos: [
      {
        id: 'od1',
        title: 'Pay the VPS invoice',
        state: 'todo',
        due: '2026-06-05T00:00:00Z',
        project_title: 'infra',
        project_slug: 'infra',
        energy: 'low',
        created_at: '2026-06-01T00:00:00Z',
        updated_at: '2026-06-01T00:00:00Z',
      },
    ],
    today_todos: [
      {
        id: 't1',
        title: 'Triage the GTD inbox',
        state: 'todo',
        project_title: 'koopa-core',
        project_slug: 'koopa-core',
        energy: 'medium',
        created_at: '2026-06-07T00:00:00Z',
        updated_at: '2026-06-07T00:00:00Z',
      },
    ],
    active_todos: [
      {
        id: 'ac1',
        title: 'Review 2 Go lessons',
        state: 'in_progress',
        project_title: '',
        project_slug: '',
        created_at: '2026-06-07T00:00:00Z',
        updated_at: '2026-06-07T00:00:00Z',
      },
    ],
    recurring_todos: [
      {
        id: 'rc1',
        title: 'Memorize Japanese vocab',
        state: 'todo',
        recur_weekdays: 127,
      },
    ],
    committed_todos: [
      {
        id: 'p1',
        plan_date: '2026-06-07',
        todo_id: 'td1',
        selected_by: 'human',
        position: 1,
        status: 'planned',
        todo_title: 'Rewrite auth handler',
        todo_state: 'in_progress',
        todo_energy: 'high',
        project_title: 'koopa-core',
        project_slug: 'koopa-core',
        created_at: '2026-06-07T00:00:00Z',
        updated_at: '2026-06-07T00:00:00Z',
      },
    ],
    completed_todos: [],
    upcoming_todos: [],
    active_goals: [
      {
        id: 'g1',
        title: 'Ship koopa v1',
        description: '',
        status: 'in_progress',
        area_name: 'Build',
        milestone_total: 5,
        milestone_done: 2,
        created_at: '2026-06-07T00:00:00Z',
        updated_at: '2026-06-07T00:00:00Z',
      },
    ],
    rss_highlights: [
      {
        title: 'Why HNSW beats IVF',
        url: 'https://example.com/hnsw',
        feed_name: 'pgvector',
        created_at: '2026-06-07T05:00:00Z',
      },
    ],
  };
}

function quietBrief(): TodayBrief {
  return {
    date: '2026-06-07',
    overdue_todos: [],
    today_todos: [],
    active_todos: [],
    recurring_todos: [],
    completed_todos: [],
    committed_todos: [],
    upcoming_todos: [],
    active_goals: [],
    rss_highlights: [],
  };
}

describe('TodayPageComponent', () => {
  let fixture: ComponentFixture<TodayPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [TodayPageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
    TestBed.resetTestingModule();
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function testid(id: string): HTMLElement | null {
    return el().querySelector(`[data-testid="${id}"]`);
  }

  async function settle(): Promise<void> {
    await fixture.whenStable();
    fixture.detectChanges();
  }

  // The Today page also fires a standalone proposals-count read for the
  // awaiting-review pointer; it must be flushed before settle for the same
  // zoneless reason below (an unflushed request hangs whenStable). The endpoint
  // returns a per-entity breakdown the service sums; the pointer only cares
  // about the total, so the whole `pending` is placed in one bucket.
  function flushCount(pending = 0): void {
    httpMock
      .expectOne((r) => r.url.endsWith(COUNT_URL))
      .flush({
        data: { proposed_goals: pending, proposed_areas: 0, proposed_projects: 0 },
      });
  }

  // Note: fixture.whenStable() must not be awaited while a request is
  // still open — pending HTTP counts as a pending task in zoneless mode
  // and whenStable would never resolve. Flush first, then settle.
  async function render(brief: TodayBrief, pendingProposals = 0): Promise<void> {
    fixture = TestBed.createComponent(TodayPageComponent);
    fixture.detectChanges();
    httpMock.expectOne((r) => r.url.endsWith(TODAY_URL)).flush(brief);
    flushCount(pendingProposals);
    await settle();
  }

  it('should show the loading skeleton while the brief is in flight', async () => {
    fixture = TestBed.createComponent(TodayPageComponent);
    fixture.detectChanges();

    expect(testid('today-loading')).toBeTruthy();
    httpMock.expectOne((r) => r.url.endsWith(TODAY_URL)).flush(quietBrief());
    flushCount();
    await settle();
  });

  it('should render the committed plan with position, title, and meta when populated', async () => {
    await render(populatedBrief());
    const plan = testid('today-plan');
    expect(plan).toBeTruthy();
    expect(plan?.textContent).toContain('Rewrite auth handler');
    expect(plan?.textContent).toContain('1');
    expect(plan?.textContent).toContain('in progress');
    expect(plan?.textContent).toContain('koopa-core');
    expect(plan?.querySelector('app-energy-meter')).toBeTruthy();
    expect(testid('today-plan-ip-dot')).toBeTruthy();
  });

  it('should derive due-based day-progress figures from the section lengths', async () => {
    await render(populatedBrief());
    const strip = testid('today-plan-completion');
    // open = due-today(1) + recurring(1) + active(1) = 3; overdue(1); completed(0)
    // → percent = round(0 / (3+1+0) * 100) = 0%. The committed plan does not count.
    expect(strip?.textContent).toContain('Open');
    expect(strip?.textContent).toContain('Completed');
    expect(strip?.textContent).toContain('Overdue');
    expect(strip?.textContent).not.toContain('Planned');
    expect(strip?.textContent).not.toContain('Deferred');
    expect(testid('today-percent')?.textContent).toContain('0%');
  });

  it('should group loose todos and style the due chips per bucket', async () => {
    await render(populatedBrief());
    const overdue = testid('today-loose-overdue');
    const dueToday = testid('today-loose-today');
    expect(overdue?.textContent).toContain('Pay the VPS invoice');
    expect(dueToday?.textContent).toContain('Triage the GTD inbox');
    expect(dueToday?.textContent).toContain('today');
    expect(testid('today-loose-upcoming')).toBeNull();
  });

  it('should render an active goal with status chip and milestone counts', async () => {
    await render(populatedBrief());
    const goals = testid('today-goals');
    expect(goals?.textContent).toContain('Ship koopa v1');
    expect(goals?.textContent).toContain('in progress');
    expect(goals?.textContent).toContain('2/5');
    expect(goals?.textContent).toContain('Build');
  });

  it('should render RSS highlights with feed name and timestamp', async () => {
    await render(populatedBrief());
    const rss = testid('today-rss');
    expect(rss?.textContent).toContain('Why HNSW beats IVF');
    expect(rss?.textContent).toContain('pgvector');
    expect(rss?.textContent).toContain('Jun 7');
  });

  it('should advance an in-progress plan row to done over HTTP when clicked', async () => {
    await render(populatedBrief());

    testid('today-plan-check')?.click();
    const req = httpMock.expectOne((r) => r.url.endsWith(ADVANCE_URL('td1')));
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ action: 'complete' });
    req.flush({});
    await settle();

    // Completing the one planned row adds it to today's completions: the strip is
    // due-based, so completed becomes 1 of (open 3 + overdue 1 + completed 1) = 20%.
    expect(testid('today-percent')?.textContent).toContain('20%');
    const notifications = TestBed.inject(NotificationService).notifications();
    expect(notifications.some((n) => n.message.includes('Marked done'))).toBe(
      true,
    );
  });

  it('should complete a loose todo through start when it has not been started', async () => {
    await render(populatedBrief());

    const checks = el().querySelectorAll<HTMLButtonElement>(
      '[data-testid="today-loose-check"]',
    );
    // Second check belongs to the Due-today bucket (todo t1, state=todo).
    checks[1]?.click();

    const start = httpMock.expectOne((r) => r.url.endsWith(ADVANCE_URL('t1')));
    expect(start.request.body).toEqual({ action: 'start' });
    start.flush({});
    const complete = httpMock.expectOne((r) =>
      r.url.endsWith(ADVANCE_URL('t1')),
    );
    expect(complete.request.body).toEqual({ action: 'complete' });
    complete.flush({});
    await settle();

    expect(testid('today-loose-today')).toBeNull();
    const notifications = TestBed.inject(NotificationService).notifications();
    expect(notifications.some((n) => n.message === 'Completed')).toBe(true);
  });

  it('should render the In progress group and complete an active todo directly when clicked', async () => {
    await render(populatedBrief());
    const active = testid('today-loose-active');
    expect(active?.textContent).toContain('Review 2 Go lessons');
    expect(active?.textContent).toContain('in progress');

    const check = active?.querySelector<HTMLButtonElement>(
      '[data-testid="today-loose-check"]',
    );
    check?.click();
    // in_progress → a single complete, never start-then-complete.
    const req = httpMock.expectOne((r) => r.url.endsWith(ADVANCE_URL('ac1')));
    expect(req.request.body).toEqual({ action: 'complete' });
    req.flush({});
    await settle();

    expect(testid('today-loose-active')).toBeNull();
  });

  it('should render recurring routines due today and complete one as an occurrence', async () => {
    await render(populatedBrief());
    const recurring = testid('today-recurring');
    expect(recurring?.textContent).toContain('Memorize Japanese vocab');
    expect(recurring?.textContent).toContain('daily');

    testid('today-recurring-check')?.click();
    const req = httpMock.expectOne((r) => r.url.endsWith(ADVANCE_URL('rc1')));
    expect(req.request.body).toEqual({ action: 'complete' });
    req.flush({});
    await settle();

    expect(testid('today-recurring')).toBeNull();
    const notifications = TestBed.inject(NotificationService).notifications();
    expect(notifications.some((n) => n.message === 'Done for today')).toBe(true);
  });

  it('should show the teaching empty state when every section is empty', async () => {
    await render(quietBrief());
    expect(testid('today-empty')).toBeTruthy();
    expect(testid('today-plan')).toBeNull();
    expect(testid('today-empty')?.textContent).toContain('Nothing planned yet');
  });

  it('should open the command palette from the capture bar', async () => {
    await render(quietBrief());
    testid('today-capture')?.click();
    expect(TestBed.inject(CommandPaletteService).isOpen()).toBe(true);
  });

  it('should recover from a failed load when retry is clicked', async () => {
    fixture = TestBed.createComponent(TodayPageComponent);
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.url.endsWith(TODAY_URL))
      .flush('boom', { status: 500, statusText: 'Server Error' });
    flushCount();
    await settle();

    expect(testid('today-error')).toBeTruthy();
    expect(testid('today-error')?.textContent).toContain(
      "Couldn't load today's plan",
    );

    testid('today-retry')?.click();
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.url.endsWith(TODAY_URL))
      .flush(populatedBrief());
    await settle();

    expect(testid('today-plan')).toBeTruthy();
  });

  it('should show the proposals pointer linking to triage when the count is positive', async () => {
    await render(quietBrief(), 3);

    const pointer = testid('today-proposals-pointer');
    expect(pointer).toBeTruthy();
    expect(pointer?.textContent).toContain('3 proposals awaiting review');
    expect(pointer?.getAttribute('href')).toBe('/admin/commitment/proposals');
  });

  it('should hide the proposals pointer when the count is zero', async () => {
    await render(populatedBrief(), 0);
    expect(testid('today-proposals-pointer')).toBeNull();
  });
});
