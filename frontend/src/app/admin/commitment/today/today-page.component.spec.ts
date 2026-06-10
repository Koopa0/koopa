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
// names, the session card appears only when active_session is present,
// and advance clicks drive the todo state machine over HTTP.

const TODAY_URL = '/api/admin/commitment/today';
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
    upcoming_todos: [],
    plan_completion: { planned: 1, completed: 0, deferred: 0 },
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
    unverified_hypotheses: [
      {
        id: 'h1',
        created_by: 'human',
        content: '',
        state: 'unverified',
        claim: 'I reach for channels when a mutex is simpler',
        invalidation_condition: 'Three drills picking the simplest primitive',
        observed_date: '2026-06-02T00:00:00Z',
        created_at: '2026-06-02T00:00:00Z',
      },
    ],
    active_session: {
      id: 's1',
      domain: 'system-design',
      mode: 'reading',
      started_at: '2026-06-07T09:00:00Z',
      created_at: '2026-06-07T09:00:00Z',
    },
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
    committed_todos: [],
    upcoming_todos: [],
    plan_completion: { planned: 0, completed: 0, deferred: 0 },
    active_goals: [],
    unverified_hypotheses: [],
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

  // Note: fixture.whenStable() must not be awaited while a request is
  // still open — pending HTTP counts as a pending task in zoneless mode
  // and whenStable would never resolve. Flush first, then settle.
  async function render(brief: TodayBrief): Promise<void> {
    fixture = TestBed.createComponent(TodayPageComponent);
    fixture.detectChanges();
    httpMock.expectOne((r) => r.url.endsWith(TODAY_URL)).flush(brief);
    await settle();
  }

  it('should show the loading skeleton while the brief is in flight', async () => {
    fixture = TestBed.createComponent(TodayPageComponent);
    fixture.detectChanges();

    expect(testid('today-loading')).toBeTruthy();
    httpMock.expectOne((r) => r.url.endsWith(TODAY_URL)).flush(quietBrief());
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

  it('should derive day-progress figures live from the committed rows', async () => {
    await render(populatedBrief());
    expect(testid('today-percent')?.textContent).toContain('0%');
    expect(testid('today-plan-completion')?.textContent).toContain('Planned');
    expect(testid('today-plan-completion')?.textContent).toContain(
      'Completed',
    );
    expect(testid('today-plan-completion')?.textContent).toContain('Deferred');
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

  it('should render a hypothesis with claim, invalidation, and unverified pill', async () => {
    await render(populatedBrief());
    const hyp = testid('today-hypotheses');
    expect(hyp?.textContent).toContain(
      'I reach for channels when a mutex is simpler',
    );
    expect(hyp?.textContent).toContain('Invalidates if');
    expect(hyp?.textContent).toContain('unverified');
  });

  it('should show the session card only when active_session is present', async () => {
    await render(populatedBrief());
    expect(testid('today-session')?.textContent).toContain('system-design');
  });

  it('should omit the session card when active_session is absent', async () => {
    const brief = quietBrief();
    brief.rss_highlights = populatedBrief().rss_highlights;
    await render(brief);
    expect(testid('today-session')).toBeNull();
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

    expect(testid('today-percent')?.textContent).toContain('100%');
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
});
