import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
  type TestRequest,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { InboxZeroPageComponent } from './inbox-zero.page';

const TODOS_URL = '/api/admin/commitment/todos';
const PLAN_URL = '/api/admin/commitment/daily-plan';

interface InboxRow {
  id: string;
  title: string;
  state: string;
  description?: string;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

function capture(over: Partial<InboxRow> & { id: string }): InboxRow {
  return {
    title: over.id,
    state: 'inbox',
    created_at: '2026-06-17T00:00:00Z',
    updated_at: '2026-06-17T00:00:00Z',
    ...over,
  };
}

function emptyPlan(): Record<string, unknown> {
  return { date: '2026-06-17', items: [], total: 0, done: 0, overdue_count: 0 };
}

describe('InboxZeroPageComponent', () => {
  let fixture: ComponentFixture<InboxZeroPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [InboxZeroPageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(InboxZeroPageComponent);
  });

  afterEach(() => {
    httpMock.verify();
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  /** Renders and lets each resource loader issue its HTTP request. */
  async function settle(): Promise<void> {
    fixture.detectChanges();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  function flushInbox(rows: InboxRow[]): void {
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(TODOS_URL))
      .flush({ data: rows });
  }

  function flushPlan(): void {
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(PLAN_URL))
      .flush({ data: emptyPlan() });
  }

  /** Settle, then answer the two load GETs (inbox queue + today's plan). */
  async function load(rows: InboxRow[]): Promise<void> {
    await settle();
    flushInbox(rows);
    flushPlan();
    await settle();
  }

  function key(k: string): void {
    document.dispatchEvent(new KeyboardEvent('keydown', { key: k }));
    fixture.detectChanges();
  }

  it('should show the loading state before the inbox resolves', async () => {
    await settle();

    expect(
      el().querySelector('[data-testid="inbox-zero-loading"]'),
    ).toBeTruthy();

    flushInbox([]);
    flushPlan();
    await settle();
  });

  it('should render the first card with source, age and counter when captures exist', async () => {
    await load([
      capture({ id: 'a', title: 'Research pgvector indexing' }),
      capture({ id: 'b', title: 'Review the PR', created_by: 'system' }),
    ]);

    expect(el().querySelector('[data-testid="inbox-zero-card"]')).toBeTruthy();
    expect(
      el().querySelector('[data-testid="inbox-zero-title"]')?.textContent,
    ).toContain('Research pgvector indexing');
    expect(
      el().querySelector('[data-testid="inbox-zero-source"]')?.textContent,
    ).toContain('capture');
    expect(
      el().querySelector('[data-testid="inbox-zero-progress"]')?.textContent,
    ).toContain('1 / 2 left');
  });

  it('should tag a system capture as a feed source', async () => {
    await load([
      capture({ id: 'a', title: 'Hermes capture', created_by: 'system' }),
    ]);

    expect(
      el().querySelector('[data-testid="inbox-zero-source"]')?.textContent,
    ).toContain('feed');
  });

  it('should render the capture description on the card when present', async () => {
    await load([
      capture({
        id: 'a',
        title: 'Research pgvector',
        description: 'check HNSW vs IVFFlat tradeoffs',
      }),
    ]);

    expect(
      el().querySelector('[data-testid="inbox-zero-description"]')?.textContent,
    ).toContain('check HNSW vs IVFFlat tradeoffs');
  });

  it('should omit the description line on the card when the capture has none', async () => {
    await load([capture({ id: 'a', title: 'No detail' })]);

    expect(
      el().querySelector('[data-testid="inbox-zero-description"]'),
    ).toBeNull();
  });

  it('should show the quiet done state when the inbox is empty', async () => {
    await load([]);

    expect(el().querySelector('[data-testid="inbox-zero-done"]')).toBeTruthy();
    expect(el().querySelector('[data-testid="inbox-zero-done"]')?.textContent).toContain(
      'Inbox zero.',
    );
    expect(el().querySelector('[data-testid="inbox-zero-card"]')).toBeNull();
  });

  it('should drop the current card on x and reload the queue', async () => {
    await load([
      capture({ id: 'a', title: 'Trash this' }),
      capture({ id: 'b', title: 'Keep this' }),
    ]);

    key('x');

    httpMock
      .expectOne((r) => r.method === 'POST' && r.url.endsWith(`${TODOS_URL}/a/advance`))
      .flush(null, { status: 204, statusText: 'No Content' });
    await settle();

    // The queue reloads with the dropped row gone.
    flushInbox([capture({ id: 'b', title: 'Keep this' })]);
    await settle();

    expect(
      el().querySelector('[data-testid="inbox-zero-title"]')?.textContent,
    ).toContain('Keep this');
    expect(
      el().querySelector('[data-testid="inbox-zero-progress"]')?.textContent,
    ).toContain('1 / 1 left');
  });

  it('should defer the current card on d', async () => {
    await load([capture({ id: 'a', title: 'Maybe later' })]);

    key('d');

    httpMock
      .expectOne(
        (r) => r.method === 'POST' && r.url.endsWith(`${TODOS_URL}/a/advance`),
      )
      .flush({ data: capture({ id: 'a', state: 'someday' }) });
    await settle();

    flushInbox([]);
    await settle();

    expect(el().querySelector('[data-testid="inbox-zero-done"]')).toBeTruthy();
  });

  it('should open the clarify dialog on c and clarify on submit', async () => {
    await load([capture({ id: 'a', title: 'Vague thought' })]);

    key('c');
    // The clarify dialog fetches the project overview when it mounts.
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.includes('/projects'))
      .flush({ data: { projects: [] } });
    await settle();

    expect(el().querySelector('[data-testid="clarify-modal"]')).toBeTruthy();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="clarify-submit"]')
      ?.click();
    await settle();

    // The dialog defaults energy to medium, so a field PUT fires first…
    const update: TestRequest = httpMock.expectOne(
      (r) => r.method === 'PUT' && r.url.endsWith(`${TODOS_URL}/a`),
    );
    expect(update.request.body).toEqual({ energy: 'medium' });
    update.flush({ data: capture({ id: 'a', state: 'inbox' }) });
    await settle();

    // …then advance(clarify) moves it inbox → todo.
    httpMock
      .expectOne(
        (r) => r.method === 'POST' && r.url.endsWith(`${TODOS_URL}/a/advance`),
      )
      .flush({ data: capture({ id: 'a', state: 'todo' }) });
    await settle();

    flushInbox([]);
    await settle();

    expect(el().querySelector('[data-testid="clarify-modal"]')).toBeNull();
    expect(el().querySelector('[data-testid="inbox-zero-done"]')).toBeTruthy();
  });

  it('should clarify then append to today on t (pull intent)', async () => {
    await load([capture({ id: 'a', title: 'Do this today' })]);

    key('t');
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.includes('/projects'))
      .flush({ data: { projects: [] } });
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="clarify-submit"]')
      ?.click();
    await settle();

    // The pull chain: field PUT (default energy), advance(clarify), then
    // the daily-plan PUT.
    httpMock
      .expectOne((r) => r.method === 'PUT' && r.url.endsWith(`${TODOS_URL}/a`))
      .flush({ data: capture({ id: 'a', state: 'inbox' }) });
    await settle();

    httpMock
      .expectOne(
        (r) => r.method === 'POST' && r.url.endsWith(`${TODOS_URL}/a/advance`),
      )
      .flush({ data: capture({ id: 'a', state: 'todo' }) });
    await settle();

    const planPut: TestRequest = httpMock.expectOne(
      (r) => r.method === 'PUT' && r.url.endsWith(PLAN_URL),
    );
    expect(planPut.request.body).toEqual({
      items: [{ todo_id: 'a', position: 0 }],
    });
    planPut.flush({
      data: { date: '2026-06-17', items: [], total: 1, items_removed: [] },
    });
    await settle();

    // Both the queue and the plan reload after a pull.
    flushInbox([]);
    flushPlan();
    await settle();

    expect(el().querySelector('[data-testid="inbox-zero-done"]')).toBeTruthy();
  });

  it('should keep the card and surface the error when an advance fails', async () => {
    await load([capture({ id: 'a', title: 'Sticky card' })]);

    key('x');

    httpMock
      .expectOne(
        (r) => r.method === 'POST' && r.url.endsWith(`${TODOS_URL}/a/advance`),
      )
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    await settle();

    // No reload fires on error — the same card is still shown.
    expect(
      el().querySelector('[data-testid="inbox-zero-title"]')?.textContent,
    ).toContain('Sticky card');
    expect(
      el().querySelector('[data-testid="inbox-zero-progress"]')?.textContent,
    ).toContain('1 / 1 left');
  });

  it('should show the error state and re-request on retry when the inbox load fails', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(TODOS_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    flushPlan();
    await settle();

    expect(el().querySelector('[data-testid="inbox-zero-error"]')).toBeTruthy();
    expect(el().querySelector('[data-testid="inbox-zero-card"]')).toBeNull();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="inbox-zero-retry"]')
      ?.click();
    await settle();

    flushInbox([capture({ id: 'a', title: 'Now it loads' })]);
    await settle();

    expect(el().querySelector('[data-testid="inbox-zero-error"]')).toBeNull();
    expect(
      el().querySelector('[data-testid="inbox-zero-title"]')?.textContent,
    ).toContain('Now it loads');
  });
});
