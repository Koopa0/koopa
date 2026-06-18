import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
  type TestRequest,
} from '@angular/common/http/testing';
import { GtdStore } from './gtd.store';
import type { TodoRow } from '../../../core/services/todo.service';

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

describe('GtdStore', () => {
  let store: GtdStore;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        GtdStore,
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    store = TestBed.inject(GtdStore);
    TestBed.tick();
    flushInitial();
  });

  afterEach(() => {
    httpMock.verify();
  });

  function flushInitial(): void {
    httpMock
      .expectOne(
        (r) => r.url.endsWith(TODOS_URL) && r.params.get('per_page') === '200',
      )
      .flush({ data: backlogRows });
    httpMock
      .expectOne((r) => r.url.includes(PLAN_URL))
      .flush({ data: planFixture });
    httpMock
      .expectOne((r) => r.url.endsWith(`${TODOS_URL}/recurring`))
      .flush({ data: { due_today: [], overdue: [] } });
    httpMock
      .expectOne((r) => r.url.endsWith(`${TODOS_URL}/history`))
      .flush({
        data: [
          {
            id: 'hist-1',
            title: 'Shipped thing',
            completed_at: '2026-06-09T10:00:00Z',
            project_title: 'koopa-core',
          },
        ],
      });
    TestBed.tick();
  }

  it('should derive live counts for every view from the loaded resources', () => {
    expect(store.counts()).toEqual({
      inbox: 1,
      today: 1,
      pending: 1,
      someday: 1,
      recurring: 0,
      history: 1,
    });
  });

  it('should reset the selection when the view changes', () => {
    store.selectedIndex.set(3);
    store.setView('pending');
    expect(store.selectedIndex()).toBe(0);
    expect(store.rows().map((r) => r.id)).toEqual(['pending-1']);
  });

  it('should capture into the inbox, switch view, and reload the backlog', () => {
    store.setView('pending');
    let cleared = 0;
    store.capture('New thought', () => cleared++);

    const post = httpMock.expectOne(
      (r) => r.url.endsWith(TODOS_URL) && r.method === 'POST',
    );
    expect(post.request.body).toEqual({ title: 'New thought' });
    post.flush({
      data: {
        id: 'new-1',
        title: 'New thought',
        state: 'inbox',
        created_by: 'human',
        created_at: '2026-06-10T08:00:00Z',
        updated_at: '2026-06-10T08:00:00Z',
      },
    });

    expect(cleared).toBe(1);
    expect(store.view()).toBe('inbox');
    TestBed.tick();
    httpMock
      .expectOne(
        (r) => r.url.endsWith(TODOS_URL) && r.params.get('per_page') === '200',
      )
      .flush({ data: backlogRows });
  });

  it('should append to the plan on pull and skip todos already planned', () => {
    store.setView('pending');
    store.pullRow(store.rows()[0]);

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
    // Reloads: backlog + plan.
    TestBed.tick();
    httpMock
      .expectOne(
        (r) => r.url.endsWith(TODOS_URL) && r.params.get('per_page') === '200',
      )
      .flush({ data: backlogRows });
    httpMock
      .expectOne((r) => r.url.includes(PLAN_URL) && r.method === 'GET')
      .flush({ data: planFixture });
    TestBed.tick();

    // planned-1 is already a member — no further PUT goes out.
    store.setView('today');
    store.pullRow(store.rows()[0]);
    httpMock.expectNone((r) => r.method === 'PUT');
  });

  it('should PUT clarify fields then advance(clarify) on modal submit', () => {
    const inboxRow = backlogRows[0];
    store.clarifyTarget.set(inboxRow);
    store.clarified({
      project_id: 'proj-1',
      energy: 'high',
      due: '2026-06-12',
    });

    const put = httpMock.expectOne(
      (r) => r.url.endsWith(`${TODOS_URL}/${inboxRow.id}`) && r.method === 'PUT',
    );
    expect(put.request.body).toEqual({
      project_id: 'proj-1',
      energy: 'high',
      due_date: '2026-06-12',
    });
    put.flush({ data: { ...inboxRow } });

    const advance = httpMock.expectOne((r) =>
      r.url.endsWith(`${TODOS_URL}/${inboxRow.id}/advance`),
    );
    expect(advance.request.body).toEqual({ action: 'clarify' });
    advance.flush({ data: { ...inboxRow, state: 'todo' } });

    expect(store.clarifyTarget()).toBeNull();
    TestBed.tick();
    httpMock
      .expectOne(
        (r) => r.url.endsWith(TODOS_URL) && r.params.get('per_page') === '200',
      )
      .flush({ data: backlogRows });
  });

  it('should clarify an inbox capture then pull it into today on t', () => {
    const inboxRow = backlogRows[0];

    // 't' on an inbox row opens clarify with pull intent — an inbox-state
    // row can't be appended to the plan directly, so nothing fires yet.
    store.pullRow(inboxRow);
    expect(store.clarifyTarget()).toBe(inboxRow);
    httpMock.expectNone((r) => r.method === 'PUT');

    // Submitting clarifies inbox→todo, then appends the new todo to today.
    store.clarified({ project_id: null, energy: null, due: null });

    const advance = httpMock.expectOne((r) =>
      r.url.endsWith(`${TODOS_URL}/${inboxRow.id}/advance`),
    );
    expect(advance.request.body).toEqual({ action: 'clarify' });
    advance.flush({ data: { ...inboxRow, state: 'todo' } });

    const put = httpMock.expectOne(
      (r) => r.url.includes(PLAN_URL) && r.method === 'PUT',
    );
    expect(put.request.body).toEqual({
      items: [
        { todo_id: 'planned-1', position: 0 },
        { todo_id: inboxRow.id, position: 1 },
      ],
    });
    put.flush({
      data: { date: todayIso, items: [], total: 2, items_removed: [] },
    });

    // Reloads: backlog + plan.
    TestBed.tick();
    httpMock
      .expectOne(
        (r) => r.url.endsWith(TODOS_URL) && r.params.get('per_page') === '200',
      )
      .flush({ data: backlogRows });
    httpMock
      .expectOne((r) => r.url.includes(PLAN_URL) && r.method === 'GET')
      .flush({ data: planFixture });
    TestBed.tick();
  });

  it('should drop an inbox capture via the advance verb and reload', () => {
    store.dropRow(backlogRows[0]);

    const advance = httpMock.expectOne((r) =>
      r.url.endsWith(`${TODOS_URL}/inbox-1/advance`),
    );
    expect(advance.request.body).toEqual({ action: 'drop' });
    advance.flush(null, { status: 204, statusText: 'No Content' });

    TestBed.tick();
    httpMock
      .expectOne(
        (r) => r.url.endsWith(TODOS_URL) && r.params.get('per_page') === '200',
      )
      .flush({ data: backlogRows });
  });

  it('should drop the clarify target then clear it on dropInstead', () => {
    store.clarifyTarget.set(backlogRows[0]);
    store.dropInstead();

    const advance = httpMock.expectOne((r) =>
      r.url.endsWith(`${TODOS_URL}/inbox-1/advance`),
    );
    expect(advance.request.body).toEqual({ action: 'drop' });
    advance.flush(null, { status: 204, statusText: 'No Content' });

    // Cleared before the reload removes the row underneath the modal.
    expect(store.clarifyTarget()).toBeNull();
    TestBed.tick();
    httpMock
      .expectOne(
        (r) => r.url.endsWith(TODOS_URL) && r.params.get('per_page') === '200',
      )
      .flush({ data: backlogRows });
  });

  it('should debounce the history search into a ?q= request', async () => {
    store.searchHistory('auth');
    httpMock.expectNone(
      (r) =>
        r.url.endsWith(`${TODOS_URL}/history`) && r.params.get('q') === 'auth',
    );

    await new Promise((resolve) => setTimeout(resolve, 300));
    TestBed.tick();

    httpMock
      .expectOne(
        (r) =>
          r.url.endsWith(`${TODOS_URL}/history`) &&
          r.params.get('q') === 'auth',
      )
      .flush({ data: [] });
  });
});

describe('GtdStore (resource error)', () => {
  let store: GtdStore;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        GtdStore,
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    store = TestBed.inject(GtdStore);
    TestBed.tick();
  });

  afterEach(() => {
    httpMock.verify();
  });

  /** Fail every init read with a 500. */
  function failInitial(): void {
    const fail = (req: TestRequest): void =>
      req.flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Server Error' },
      );
    httpMock
      .match((r) => r.url.endsWith(TODOS_URL) && r.params.get('per_page') === '200')
      .forEach(fail);
    httpMock.match((r) => r.url.includes(PLAN_URL)).forEach(fail);
    httpMock.match((r) => r.url.endsWith(`${TODOS_URL}/recurring`)).forEach(fail);
    httpMock.match((r) => r.url.endsWith(`${TODOS_URL}/history`)).forEach(fail);
    TestBed.tick();
  }

  it('should fall back to empty rows/counts/historyRows without throwing when every read errors', () => {
    failInitial();

    // rows() reads the guarded backlogValue() (hasValue() ? value() : []) —
    // it must return [] rather than throw a ResourceValueError.
    expect(store.rows()).toEqual([]);
    // historyRows() is the guarded historyValue() fallback.
    expect(store.historyRows()).toEqual([]);
    // counts() composes the guarded fallbacks — every view counts to 0.
    expect(store.counts()).toEqual({
      inbox: 0,
      today: 0,
      pending: 0,
      someday: 0,
      recurring: 0,
      history: 0,
    });
  });
});
