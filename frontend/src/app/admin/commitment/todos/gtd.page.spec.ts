import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { ActivatedRoute } from '@angular/router';
import { GtdPageComponent } from './gtd.page';
import { todayInTaipei } from './gtd-view';
import type { TodoRow } from '../../../core/services/todo.service';

// Pins the Todos surface against the commitment contract: the backlog
// list (per_page=200), the daily plan (today membership + t append), and
// the resolved history (Complete tab) with ?q= search.

const TODOS_URL = '/api/admin/commitment/todos';
const PLAN_URL = '/api/admin/commitment/daily-plan';

// Mint the seed "today" on the SAME civil-date basis production uses
// (Asia/Taipei via todayInTaipei) — NOT new Date().toISOString() (UTC). The two
// diverge during 16:00–23:59 UTC, which would drop the due-today seed from the
// Today tab and flake the count assertion only in that wall-clock window.
const todayIso = todayInTaipei();

const backlogRows: TodoRow[] = [
  {
    id: 'inbox-1',
    title: 'Raw capture',
    state: 'inbox',
    created_at: '2026-06-10T07:00:00Z',
    updated_at: '2026-06-10T07:00:00Z',
  },
  {
    id: 'inbox-2',
    title: 'Second capture',
    state: 'inbox',
    created_at: '2026-06-10T07:30:00Z',
    updated_at: '2026-06-10T07:30:00Z',
  },
  {
    id: 'planned-1',
    title: 'Planned thing',
    state: 'in_progress',
    created_at: '2026-06-09T07:00:00Z',
    updated_at: '2026-06-09T07:00:00Z',
  },
  {
    id: 'pending-1',
    title: 'Pending todo',
    state: 'todo',
    project_title: 'koopa-core',
    energy: 'medium',
    due: '2099-01-01T00:00:00Z',
    created_at: '2026-06-08T07:00:00Z',
    updated_at: '2026-06-08T07:00:00Z',
  },
  {
    id: 'routine-1',
    title: 'Daily review',
    state: 'todo',
    recur_interval: 1,
    recur_unit: 'days',
    due: `${todayIso}T00:00:00Z`,
    created_at: '2026-06-01T07:00:00Z',
    updated_at: '2026-06-01T07:00:00Z',
  },
  {
    id: 'someday-1',
    title: 'Someday idea',
    state: 'someday',
    created_at: '2026-06-01T07:00:00Z',
    updated_at: '2026-06-01T07:00:00Z',
  },
];

const planFixture = {
  date: todayIso,
  items: [
    {
      id: 'dp-1',
      todo_id: 'planned-1',
      title: 'Planned thing',
      state: 'planned',
      selected_by: 'human',
    },
  ],
  total: 1,
  done: 0,
  overdue_count: 0,
};

const historyFixture = [
  {
    id: 'hist-1',
    title: 'Shipped thing',
    state: 'done',
    completed_at: '2026-06-09T10:00:00Z',
    project_title: 'koopa-core',
  },
  {
    id: 'hist-2',
    title: 'Won’t pursue this',
    state: 'dismissed',
    completed_at: '2026-06-09T09:00:00Z',
    project_title: '',
  },
];

describe('GtdPageComponent', () => {
  let fixture: ComponentFixture<GtdPageComponent>;
  let httpMock: HttpTestingController;

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

  // Flush the three initial loads (backlog, plan, resolved history), then
  // settle (whenStable must not be awaited while a request is still open in
  // zoneless mode). Inbox is its own page now — the Todos page has no
  // recurring resource.
  async function render(initialView: string): Promise<void> {
    TestBed.configureTestingModule({
      imports: [GtdPageComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        {
          provide: ActivatedRoute,
          useValue: { snapshot: { data: { gtdView: initialView } } },
        },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(GtdPageComponent);
    fixture.detectChanges();
    httpMock
      .expectOne(
        (r) =>
          r.url.endsWith(TODOS_URL) &&
          r.params.get('per_page') === '200' &&
          r.params.get('state') === 'inbox,todo,in_progress,someday',
      )
      .flush({ data: backlogRows });
    httpMock
      .expectOne((r) => r.url.includes(PLAN_URL))
      .flush({ data: planFixture });
    httpMock
      .expectOne((r) => r.url.endsWith(`${TODOS_URL}/history`))
      .flush({ data: historyFixture });
    await settle();
  }

  function flushBacklogReload(): void {
    httpMock
      .expectOne(
        (r) =>
          r.url.endsWith(TODOS_URL) &&
          r.params.get('per_page') === '200' &&
          r.params.get('state') === 'inbox,todo,in_progress,someday',
      )
      .flush({ data: backlogRows });
  }

  function keydown(key: string): void {
    document.dispatchEvent(new KeyboardEvent('keydown', { key }));
    fixture.detectChanges();
  }

  it('should land on Pending by default with the status tabs and live counts', async () => {
    // Unknown/legacy route data coerces to the default Pending view.
    await render('today');

    expect(testid('gtd-tab-pending')?.getAttribute('aria-selected')).toBe(
      'true',
    );
    // Pending = the one non-recurring, unplanned todo; routine-1 (recurring) and
    // planned-1 (in_progress, in the plan) are excluded.
    expect(testid('gtd-tab-pending')?.textContent).toContain('1');
    expect(testid('gtd-tab-in_progress')?.textContent).toContain('1');
    expect(testid('gtd-tab-someday')?.textContent).toContain('1');
    expect(testid('gtd-tab-history')?.textContent).toContain('2');
    // Inbox / Today / Recurring are no longer tabs on the Todos page.
    expect(testid('gtd-tab-inbox')).toBeNull();
    expect(testid('gtd-tab-today')).toBeNull();
    expect(testid('gtd-tab-recurring')).toBeNull();
    expect(testid('gtd-row-0')?.textContent).toContain('Pending todo');
  });

  it('should render the In Progress tab with started, non-recurring work', async () => {
    await render('in_progress');

    expect(testid('gtd-tab-in_progress')?.getAttribute('aria-selected')).toBe(
      'true',
    );
    const list = testid('gtd-list');
    expect(list?.textContent).toContain('Planned thing');
    expect(list?.textContent).not.toContain('Pending todo');
    expect(list?.textContent).not.toContain('Daily review');
  });

  it('should render the Complete tab with resolution-kind badges', async () => {
    await render('history');

    expect(testid('gtd-history-row')?.textContent).toContain('Shipped thing');
    // done → green check; dropped (dismissed) → muted ✕.
    expect(testid('gtd-history-kind-done')?.textContent).toContain('✓');
    expect(testid('gtd-history-kind-dropped')?.textContent).toContain('✕');
  });

  it('should not render a capture bar on the Todos page', async () => {
    await render('pending');
    expect(testid('gtd-capture-input')).toBeNull();
  });

  it('should move the selection with j/k in a status view', async () => {
    await render('someday');
    // Seed two someday rows so j has somewhere to move.
    expect(testid('gtd-row-0')?.getAttribute('data-selected')).toBe('true');
    keydown('j');
    // Only one someday row in the fixture, so selection stays clamped at 0.
    expect(testid('gtd-row-0')?.getAttribute('data-selected')).toBe('true');
  });

  it('should pull the selected pending todo into today with t via the atomic plan PUT', async () => {
    await render('pending');
    keydown('t');

    const put = httpMock.expectOne(
      (r) => r.url.includes(PLAN_URL) && r.method === 'PUT',
    );
    expect(put.request.body).toEqual({
      items: [
        { todo_id: 'planned-1', position: 0 },
        { todo_id: 'pending-1', position: 1 },
      ],
    });
    put.flush({
      data: { date: todayIso, items: [], total: 2, items_removed: [] },
    });
    TestBed.tick();
    flushBacklogReload();
    httpMock
      .expectOne((r) => r.url.includes(PLAN_URL) && r.method === 'GET')
      .flush({ data: planFixture });
    await settle();
  });

  it('should activate a someday row with e via advance(activate)', async () => {
    await render('someday');
    expect(testid('gtd-row-0')?.textContent).toContain('Someday idea');

    keydown('e');
    const advance = httpMock.expectOne((r) =>
      r.url.endsWith(`${TODOS_URL}/someday-1/advance`),
    );
    expect(advance.request.body).toEqual({ action: 'activate' });
    advance.flush({ data: { ...backlogRows[5], state: 'todo' } });
    TestBed.tick();
    flushBacklogReload();
    await settle();
  });

  it('should show the Complete search box and run a debounced ?q= search', async () => {
    await render('history');
    expect(testid('gtd-history-row')?.textContent).toContain('Shipped thing');

    const search = testid('gtd-history-search') as HTMLInputElement;
    search.value = 'auth';
    search.dispatchEvent(new Event('input'));
    fixture.detectChanges();

    // Poll for the debounced request instead of sleeping a fixed interval — a
    // wall-clock wait races the 250ms debounce under full-suite worker load
    // (the documented flake). vi.waitFor retries until the request is issued.
    const req = await vi.waitFor(
      () => {
        fixture.detectChanges();
        return httpMock.expectOne(
          (r) =>
            r.url.endsWith(`${TODOS_URL}/history`) &&
            r.params.get('q') === 'auth',
        );
      },
      { timeout: 3000, interval: 20 },
    );
    req.flush({ data: [] });
    await settle();

    expect(el().textContent).toContain('No resolved todos match your search.');
  });
});
