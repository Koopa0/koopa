import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';

import { TodayPageComponent } from './today-page.component';
import { TodayService, type TodayBrief } from './today.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';

// Pins the Today render at the PRODUCT surface against the brief(morning)
// contract (GET /api/admin/commitment/today). A VM bound to the retired
// fan-out shape (awaitingJudgment / warnings) would not render these
// sections, failing these assertions.

function populatedBrief(): TodayBrief {
  return {
    date: '2026-06-07',
    overdue_todos: [],
    today_todos: [
      {
        id: 't1',
        title: 'Triage the GTD inbox',
        state: 'todo',
        project_title: 'koopa-core',
        project_slug: 'koopa-core',
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
        project_title: 'koopa-core',
        project_slug: 'koopa-core',
        created_at: '2026-06-07T00:00:00Z',
        updated_at: '2026-06-07T00:00:00Z',
      },
    ],
    upcoming_todos: [],
    plan_completion: { planned: 3, completed: 1, deferred: 0 },
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
        created_at: '4h ago',
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

  afterEach(() => TestBed.resetTestingModule());

  async function render(brief: TodayBrief): Promise<HTMLElement> {
    TestBed.configureTestingModule({
      imports: [TodayPageComponent],
      providers: [
        provideRouter([]),
        { provide: TodayService, useValue: { today: () => of(brief) } },
        {
          provide: AdminTopbarService,
          useValue: { set: () => undefined, reset: () => undefined },
        },
      ],
    });
    fixture = TestBed.createComponent(TodayPageComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  function testid(el: HTMLElement, id: string): HTMLElement | null {
    return el.querySelector(`[data-testid="${id}"]`);
  }

  it('should render the committed plan from todo_title when populated', async () => {
    const el = await render(populatedBrief());
    const plan = testid(el, 'today-plan');
    expect(plan).toBeTruthy();
    expect(plan?.textContent).toContain('Rewrite auth handler');
  });

  it('should render an active goal and the active session when present', async () => {
    const el = await render(populatedBrief());
    expect(testid(el, 'today-goals')?.textContent).toContain('Ship koopa v1');
    expect(testid(el, 'today-session')?.textContent).toContain('system-design');
  });

  it('should render an unverified hypothesis claim', async () => {
    const el = await render(populatedBrief());
    expect(testid(el, 'today-hypotheses')?.textContent).toContain(
      'I reach for channels when a mutex is simpler',
    );
  });

  it('should show the teaching empty state when every section is empty', async () => {
    const el = await render(quietBrief());
    expect(testid(el, 'today-empty')).toBeTruthy();
    expect(testid(el, 'today-plan')).toBeNull();
  });
});
