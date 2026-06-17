import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { ActivatedRoute } from '@angular/router';
import { GtdPageComponent } from './gtd.page';
import type { TodoRow } from '../../../core/services/todo.service';

// Pins the GTD surface against the commitment contract: the backlog
// list (per_page=200), the daily plan (today membership + t append),
// the recurring buckets, and the completed history with ?q= search.

const TODOS_URL = '/api/admin/commitment/todos';
const PLAN_URL = '/api/admin/commitment/daily-plan';

const todayIso = new Date().toISOString().slice(0, 10);

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

const recurringFixture = {
  due_today: [
    {
      id: 'routine-1',
      title: 'Daily review',
      state: 'todo',
      recur_interval: 1,
      recur_unit: 'days',
      created_by: 'human',
      created_at: '2026-06-01T07:00:00Z',
      updated_at: '2026-06-01T07:00:00Z',
    },
  ],
  overdue: [],
};

const historyFixture = [
  {
    id: 'hist-1',
    title: 'Shipped thing',
    completed_at: '2026-06-09T10:00:00Z',
    project_title: 'koopa-core',
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

  // Flush the four initial loads, then settle (whenStable must not be
  // awaited while a request is still open in zoneless mode).
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
      .expectOne((r) => r.url.endsWith(`${TODOS_URL}/recurring`))
      .flush({ data: recurringFixture });
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

  it('should land on the Inbox view from the inbox route data with live counts', async () => {
    await render('inbox');

    expect(testid('gtd-tab-inbox')?.getAttribute('aria-selected')).toBe('true');
    expect(testid('gtd-tab-inbox')?.textContent).toContain('2');
    expect(testid('gtd-tab-today')?.textContent).toContain('2');
    expect(testid('gtd-tab-pending')?.textContent).toContain('1');
    expect(testid('gtd-tab-someday')?.textContent).toContain('1');
    expect(testid('gtd-tab-recurring')?.textContent).toContain('1');
    expect(testid('gtd-tab-history')?.textContent).toContain('1');
    expect(testid('gtd-row-0')?.textContent).toContain('Raw capture');
    expect(testid('gtd-count')?.textContent).toContain('2 items');
  });

  it('should land on the Today view from the todos route data', async () => {
    await render('today');

    expect(testid('gtd-tab-today')?.getAttribute('aria-selected')).toBe(
      'true',
    );
    const list = testid('gtd-list');
    expect(list?.textContent).toContain('Planned thing');
    expect(list?.textContent).toContain('Daily review');
    expect(list?.textContent).not.toContain('Pending todo');
  });

  it('should capture on Enter, switch to Inbox, and reload the backlog', async () => {
    await render('today');

    const input = testid('gtd-capture-input') as HTMLInputElement;
    input.value = 'Look into NATS JetStream';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    (testid('gtd-capture-form') as HTMLFormElement).dispatchEvent(
      new Event('submit'),
    );

    const post = httpMock.expectOne(
      (r) => r.url.endsWith(TODOS_URL) && r.method === 'POST',
    );
    expect(post.request.body).toEqual({ title: 'Look into NATS JetStream' });
    post.flush({
      data: {
        id: 'new-1',
        title: 'Look into NATS JetStream',
        state: 'inbox',
        created_by: 'human',
        created_at: '2026-06-10T08:00:00Z',
        updated_at: '2026-06-10T08:00:00Z',
      },
    });
    TestBed.tick();
    flushBacklogReload();
    await settle();

    expect(testid('gtd-tab-inbox')?.getAttribute('aria-selected')).toBe(
      'true',
    );
    expect((testid('gtd-capture-input') as HTMLInputElement).value).toBe('');
  });

  it('should move the selection with j and drop the selected capture with x', async () => {
    await render('inbox');

    expect(testid('gtd-row-0')?.getAttribute('data-selected')).toBe('true');
    keydown('j');
    expect(testid('gtd-row-1')?.getAttribute('data-selected')).toBe('true');
    keydown('k');
    expect(testid('gtd-row-0')?.getAttribute('data-selected')).toBe('true');

    keydown('x');
    const advance = httpMock.expectOne((r) =>
      r.url.endsWith(`${TODOS_URL}/inbox-1/advance`),
    );
    expect(advance.request.body).toEqual({ action: 'drop' });
    advance.flush(null, { status: 204, statusText: 'No Content' });
    TestBed.tick();
    flushBacklogReload();
    await settle();
  });

  it('should ignore triage keys while typing in the capture bar', async () => {
    await render('inbox');

    const input = testid('gtd-capture-input') as HTMLInputElement;
    input.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'x', bubbles: true }),
    );
    fixture.detectChanges();

    httpMock.expectNone((r) => r.url.includes('/advance'));
  });

  it('should open the clarify modal with e and run PUT + advance(clarify) on submit', async () => {
    await render('inbox');

    keydown('e');
    httpMock
      .expectOne((r) => r.url.includes('/api/admin/commitment/projects'))
      .flush({ data: { projects: [] } });
    await settle();
    expect(testid('clarify-modal')).toBeTruthy();

    (testid('clarify-submit') as HTMLButtonElement).click();
    // Energy defaults to medium, so the field PUT precedes the advance.
    const put = httpMock.expectOne(
      (r) =>
        r.url.endsWith(`${TODOS_URL}/inbox-1`) && r.method === 'PUT',
    );
    expect(put.request.body).toEqual({ energy: 'medium' });
    put.flush({ data: { ...backlogRows[0] } });
    const advance = httpMock.expectOne((r) =>
      r.url.endsWith(`${TODOS_URL}/inbox-1/advance`),
    );
    expect(advance.request.body).toEqual({ action: 'clarify' });
    advance.flush({ data: { ...backlogRows[0], state: 'todo' } });
    TestBed.tick();
    flushBacklogReload();
    await settle();

    expect(testid('clarify-modal')).toBeNull();
  });

  it('should pull the selected pending todo into today with t via the atomic plan PUT', async () => {
    await render('inbox');

    (testid('gtd-tab-pending') as HTMLButtonElement).click();
    fixture.detectChanges();
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
    await render('inbox');

    (testid('gtd-tab-someday') as HTMLButtonElement).click();
    fixture.detectChanges();
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

  it('should show the history search box and run a debounced ?q= search', async () => {
    await render('inbox');

    (testid('gtd-tab-history') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(testid('gtd-history-row')?.textContent).toContain('Shipped thing');

    const search = testid('gtd-history-search') as HTMLInputElement;
    search.value = 'auth';
    search.dispatchEvent(new Event('input'));
    fixture.detectChanges();

    await new Promise((resolve) => setTimeout(resolve, 300));
    httpMock
      .expectOne(
        (r) =>
          r.url.endsWith(`${TODOS_URL}/history`) &&
          r.params.get('q') === 'auth',
      )
      .flush({ data: [] });
    await settle();

    expect(el().textContent).toContain('No completed todos match your search.');
  });

  it('should render the recurring buckets with the every-N badge and no row actions', async () => {
    await render('inbox');

    (testid('gtd-tab-recurring') as HTMLButtonElement).click();
    fixture.detectChanges();

    expect(testid('gtd-recurring-group-Due today')).toBeTruthy();
    const row = testid('gtd-recurring-row');
    expect(row?.textContent).toContain('Daily review');
    expect(row?.textContent).toContain('every 1d');
    expect(row?.querySelector('button')).toBeNull();
  });
});
