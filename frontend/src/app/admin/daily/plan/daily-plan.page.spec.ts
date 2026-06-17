import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
  type TestRequest,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import type { CdkDragDrop } from '@angular/cdk/drag-drop';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { DailyPlanPageComponent } from './daily-plan.page';
import { NotificationService } from '../../../core/services/notification.service';
import type {
  DailyPlan,
  DailyPlanEntry,
} from '../../../core/services/daily-plan.service';
import type { TodoRow } from '../../../core/services/todo.service';

// Pins the daily-plan builder against the existing endpoints: GET
// /commitment/daily-plan (today's plan), GET /commitment/todos?state=todo
// (add candidates), and the atomic PUT /commitment/daily-plan for
// reorder/add/remove. Only the HTTP boundary is mocked; the component,
// DailyPlanService, TodoService, signals, and CDK reorder logic are real.

const PLAN_URL = '/api/admin/commitment/daily-plan';
const TODOS_URL = '/api/admin/commitment/todos';

function entry(over: Partial<DailyPlanEntry> = {}): DailyPlanEntry {
  return {
    id: over.id ?? 'e-' + (over.todo_id ?? 't'),
    todo_id: over.todo_id ?? 't',
    title: over.title ?? 'A todo',
    state: over.state ?? 'planned',
    selected_by: 'human',
    ...over,
  };
}

function plan(items: DailyPlanEntry[]): DailyPlan {
  return {
    date: '2026-06-17',
    items,
    total: items.length,
    done: items.filter((i) => i.state === 'done').length,
    overdue_count: 0,
  };
}

function todoRow(over: Partial<TodoRow> = {}): TodoRow {
  return {
    id: over.id ?? 'cand',
    title: over.title ?? 'A candidate',
    state: over.state ?? 'todo',
    created_at: '2026-06-17T00:00:00Z',
    updated_at: '2026-06-17T00:00:00Z',
    ...over,
  };
}

describe('DailyPlanPageComponent', () => {
  let fixture: ComponentFixture<DailyPlanPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [DailyPlanPageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        NotificationService,
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

  /** Flush the two init reads: the plan GET and the candidate-todos GET. */
  function flushInit(planItems: DailyPlanEntry[], todos: TodoRow[]): void {
    const planReq = httpMock.expectOne(
      (r) => r.url.endsWith(PLAN_URL) && r.method === 'GET',
    );
    planReq.flush({ data: plan(planItems) });

    const todosReq = httpMock.expectOne(
      (r) => r.url.endsWith(TODOS_URL) && r.method === 'GET',
    );
    todosReq.flush({ data: todos });
  }

  async function render(
    planItems: DailyPlanEntry[],
    todos: TodoRow[] = [],
  ): Promise<void> {
    fixture = TestBed.createComponent(DailyPlanPageComponent);
    fixture.detectChanges();
    flushInit(planItems, todos);
    await settle();
  }

  it('should show the loading skeleton while the plan is in flight', () => {
    fixture = TestBed.createComponent(DailyPlanPageComponent);
    fixture.detectChanges();
    expect(testid('daily-plan-loading')).toBeTruthy();
    flushInit([], []);
  });

  it('should render only planned entries, newest history hidden', async () => {
    await render([
      entry({ todo_id: 'p1', title: 'Ship migration', state: 'planned' }),
      entry({ todo_id: 'done1', title: 'Already done', state: 'done' }),
    ]);

    expect(testid('daily-plan-item-p1')).toBeTruthy();
    expect(testid('daily-plan-item-done1')).toBeNull();
    expect(testid('daily-plan-count')?.textContent).toContain('1 planned');
  });

  it('should show the empty state when no planned entries exist', async () => {
    await render([entry({ todo_id: 'd', state: 'dropped' })]);
    expect(testid('daily-plan-empty')).toBeTruthy();
    expect(testid('daily-plan-count')?.textContent).toContain('0 planned');
  });

  it('should show the error state when the plan fails to load', async () => {
    fixture = TestBed.createComponent(DailyPlanPageComponent);
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.url.endsWith(PLAN_URL) && r.method === 'GET')
      .flush(null, { status: 500, statusText: 'Server Error' });
    // The candidate-todos GET still fires; drain it so verify() is clean.
    httpMock
      .match((r) => r.url.endsWith(TODOS_URL) && r.method === 'GET')
      .forEach((r) => r.flush({ data: [] }));
    await settle();

    expect(testid('daily-plan-error')).toBeTruthy();
  });

  it('should reorder via the atomic PUT and re-render from the envelope', async () => {
    await render([
      entry({ todo_id: 'a', title: 'First', state: 'planned' }),
      entry({ todo_id: 'b', title: 'Second', state: 'planned' }),
    ]);

    // Drive the CDK drop handler: move index 1 above index 0.
    const event = {
      previousIndex: 1,
      currentIndex: 0,
    } as CdkDragDrop<DailyPlanEntry[]>;
    // drop() is the public-template handler; calling it exercises the same
    // path the drag gesture would, without a DOM drag harness.
    (
      fixture.componentInstance as unknown as {
        drop(e: CdkDragDrop<DailyPlanEntry[]>): Promise<void>;
      }
    ).drop(event);

    const put = httpMock.expectOne(
      (r) => r.url.endsWith(PLAN_URL) && r.method === 'PUT',
    );
    expectPutOrder(put, ['b', 'a']);
    put.flush({
      data: {
        date: '2026-06-17',
        items: [
          entry({ todo_id: 'b', title: 'Second', state: 'planned' }),
          entry({ todo_id: 'a', title: 'First', state: 'planned' }),
        ],
        total: 2,
        items_removed: [],
      },
    });
    await settle();

    const labels = [...el().querySelectorAll('[data-testid^="daily-plan-item-"]')]
      .map((node) => node.textContent ?? '')
      .join(' | ');
    expect(labels.indexOf('Second')).toBeLessThan(labels.indexOf('First'));
  });

  it('should add an un-planned todo through the PUT', async () => {
    await render(
      [entry({ todo_id: 'p1', title: 'Existing', state: 'planned' })],
      [todoRow({ id: 'new', title: 'Fresh todo' })],
    );

    testid('daily-plan-add-toggle')!.dispatchEvent(new Event('click'));
    fixture.detectChanges();
    testid('daily-plan-candidate-new')!.dispatchEvent(new Event('click'));

    const put = httpMock.expectOne(
      (r) => r.url.endsWith(PLAN_URL) && r.method === 'PUT',
    );
    expectPutOrder(put, ['p1', 'new']);
    put.flush({
      data: {
        date: '2026-06-17',
        items: [
          entry({ todo_id: 'p1', title: 'Existing', state: 'planned' }),
          entry({ todo_id: 'new', title: 'Fresh todo', state: 'planned' }),
        ],
        total: 2,
        items_removed: [],
      },
    });
    await settle();

    expect(testid('daily-plan-item-new')).toBeTruthy();
  });

  it('should remove a planned item through the PUT', async () => {
    await render([
      entry({ todo_id: 'keep', title: 'Keep', state: 'planned' }),
      entry({ todo_id: 'gone', title: 'Remove me', state: 'planned' }),
    ]);

    testid('daily-plan-remove-gone')!.dispatchEvent(new Event('click'));

    const put = httpMock.expectOne(
      (r) => r.url.endsWith(PLAN_URL) && r.method === 'PUT',
    );
    expectPutOrder(put, ['keep']);
    put.flush({
      data: {
        date: '2026-06-17',
        items: [entry({ todo_id: 'keep', title: 'Keep', state: 'planned' })],
        total: 1,
        items_removed: [{ id: 'e-gone', todo_id: 'gone', todo_title: 'Remove me' }],
      },
    });
    await settle();

    expect(testid('daily-plan-item-gone')).toBeNull();
    expect(testid('daily-plan-item-keep')).toBeTruthy();
  });

  it('should disable removing the last planned item (empty PUT is rejected)', async () => {
    await render([entry({ todo_id: 'only', title: 'Lonely', state: 'planned' })]);

    const button = testid('daily-plan-remove-only') as HTMLButtonElement | null;
    expect(button).toBeTruthy();
    expect(button!.disabled).toBe(true);
    // No PUT fires; verify() in afterEach asserts no outstanding request.
  });
});

/** Assert the PUT body's items carry the expected todo order. */
function expectPutOrder(req: TestRequest, order: string[]): void {
  const body = req.request.body as { items: { todo_id: string }[] };
  expect(body.items.map((i) => i.todo_id)).toEqual(order);
}
