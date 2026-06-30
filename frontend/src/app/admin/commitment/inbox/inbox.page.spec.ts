import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { InboxPageComponent } from './inbox.page';
import type { TodoRow } from '../../../core/services/todo.service';

// Pins the dedicated Inbox page against the commitment contract: the
// backlog list feeds the inbox view (per_page=200, every live state), the
// capture bar POSTs a raw todo, and an inbox row's Clarify opens the
// clarify dialog. The store spins up its three resources, so the plan /
// history reads are flushed even though the inbox surface never shows them.

const TODOS_URL = '/api/admin/commitment/todos';
const PLAN_URL = '/api/admin/commitment/daily-plan';
const PROJECTS_URL = '/api/admin/commitment/projects';

const backlogRows: TodoRow[] = [
  {
    id: 'inbox-1',
    title: 'Raw capture',
    state: 'inbox',
    created_by: 'human',
    created_at: '2026-06-10T07:00:00Z',
    updated_at: '2026-06-10T07:00:00Z',
  },
  {
    id: 'inbox-2',
    title: 'Second capture',
    state: 'inbox',
    created_by: 'hermes',
    created_at: '2026-06-10T07:30:00Z',
    updated_at: '2026-06-10T07:30:00Z',
  },
];

const planFixture = {
  date: '2026-06-30',
  items: [],
  total: 0,
  done: 0,
  overdue_count: 0,
};

const historyFixture: unknown[] = [];

describe('InboxPageComponent', () => {
  let fixture: ComponentFixture<InboxPageComponent>;
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

  function flushBacklog(): void {
    httpMock
      .expectOne(
        (r) =>
          r.url.endsWith(TODOS_URL) &&
          r.params.get('per_page') === '200' &&
          r.params.get('state') === 'inbox,todo,in_progress,someday',
      )
      .flush({ data: backlogRows });
  }

  // Flush the three initial backlog-store loads, then settle (whenStable
  // must not be awaited while a request is still open in zoneless mode).
  async function render(): Promise<void> {
    TestBed.configureTestingModule({
      imports: [InboxPageComponent],
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(InboxPageComponent);
    fixture.detectChanges();
    flushBacklog();
    httpMock
      .expectOne((r) => r.url.includes(PLAN_URL))
      .flush({ data: planFixture });
    httpMock
      .expectOne((r) => r.url.endsWith(`${TODOS_URL}/history`))
      .flush({ data: historyFixture });
    await settle();
  }

  it('should render the inbox rows with the inbox count when loaded', async () => {
    await render();

    expect(testid('gtd-row-0')?.textContent).toContain('Raw capture');
    expect(testid('gtd-row-1')?.textContent).toContain('Second capture');
    expect(testid('gtd-count')?.textContent).toContain('2 items');
  });

  it('should post the capture to the create endpoint and clear the bar', async () => {
    await render();

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
    flushBacklog();
    await settle();

    expect((testid('gtd-capture-input') as HTMLInputElement).value).toBe('');
    expect(testid('gtd-list')?.textContent).toContain('Raw capture');
  });

  it('should open the clarify modal when an inbox row Clarify is clicked', async () => {
    await render();

    (testid('gtd-row-clarify') as HTMLButtonElement).click();
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.url.includes(PROJECTS_URL))
      .flush({ data: [] });
    await settle();

    expect(testid('clarify-modal')).toBeTruthy();
  });
});
