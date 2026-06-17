import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
  type TestRequest,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { DayClosePageComponent } from './day-close.page';
import { NotificationService } from '../../../core/services/notification.service';
import type {
  DailyPlan,
  DailyPlanEntry,
} from '../../../core/services/daily-plan.service';
import { DAY_CLOSE_LOOKBACK_DAYS } from './day-close-view';

// Pins the Day-close render + actions against the existing endpoints
// (GET /commitment/daily-plan per lookback date, PUT /commitment/daily-plan,
// POST todos/{id}/advance, POST knowledge/notes). The page probes 14 past
// days on init; the spec flushes each probe and asserts the confrontation
// surfaces only days with unresolved planned items.

const PLAN_URL = '/api/admin/commitment/daily-plan';
const ADVANCE_URL = (id: string) =>
  `/api/admin/commitment/todos/${id}/advance`;
const NOTES_URL = '/api/admin/knowledge/notes';

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

function plan(date: string, items: DailyPlanEntry[]): DailyPlan {
  return { date, items, total: items.length, done: 0, overdue_count: 0 };
}

describe('DayClosePageComponent', () => {
  let fixture: ComponentFixture<DayClosePageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [DayClosePageComponent],
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

  /**
   * Flush all lookback probes. `plansByDate` supplies a plan for any date
   * that has one; every other probed date gets an empty plan. Returns the
   * set of dates that were probed.
   */
  function flushProbes(plansByDate: Record<string, DailyPlan>): void {
    const reqs = httpMock.match(
      (r) => r.url.endsWith(PLAN_URL) && r.method === 'GET',
    );
    expect(reqs).toHaveLength(DAY_CLOSE_LOOKBACK_DAYS);
    for (const req of reqs) {
      const date = req.request.params.get('date') ?? '';
      req.flush(plansByDate[date] ?? plan(date, []));
    }
  }

  async function render(
    plansByDate: Record<string, DailyPlan>,
  ): Promise<void> {
    fixture = TestBed.createComponent(DayClosePageComponent);
    fixture.detectChanges();
    flushProbes(plansByDate);
    await settle();
  }

  it('should show the loading skeleton while probes are in flight', () => {
    fixture = TestBed.createComponent(DayClosePageComponent);
    fixture.detectChanges();
    expect(testid('day-close-loading')).toBeTruthy();
    flushProbes({});
  });

  it('should show the clear empty state when no day has unresolved items', async () => {
    // Every probed day is empty → nothing to confront.
    await render({});
    expect(testid('day-close-clear')).toBeTruthy();
    expect(testid('day-close-count')).toBeNull();
  });

  it('should confront only days that have unresolved planned items', async () => {
    // Pick two concrete dates inside the 14-day window relative to now.
    const dates = probeDatesFromNow();
    const withOpen = dates[0];
    const allDone = dates[1];

    await render({
      [withOpen]: plan(withOpen, [
        entry({ todo_id: 'open-1', title: 'Ship the thing', state: 'planned' }),
        entry({ todo_id: 'done-1', title: 'Already done', state: 'done' }),
      ]),
      [allDone]: plan(allDone, [
        entry({ todo_id: 'd', state: 'dropped' }),
      ]),
    });

    // The day with an unresolved item is confronted; the terminal-only day is not.
    expect(testid('day-close-day-' + withOpen)).toBeTruthy();
    expect(testid('day-close-day-' + allDone)).toBeNull();
    // Only the unresolved item renders, not the done sibling.
    expect(testid('day-close-item-open-1')).toBeTruthy();
    expect(testid('day-close-item-done-1')).toBeNull();
    expect(testid('day-close-count')?.textContent).toContain('1 unresolved');
  });

  it('should re-plan an item to today and remove it from the confrontation', async () => {
    const dates = probeDatesFromNow();
    const day = dates[0];
    await render({
      [day]: plan(day, [
        entry({ todo_id: 'rp-1', title: 'Re-plan me', state: 'planned' }),
      ]),
    });

    testid('day-close-replan-rp-1')!.dispatchEvent(new Event('click'));

    // Action reads today's plan (no date param) then PUTs the append. The
    // PUT is dispatched only after the awaited today-GET promise resolves,
    // so settle between the two requests before expecting the PUT.
    const todayGet = httpMock.expectOne(
      (r) =>
        r.url.endsWith(PLAN_URL) && r.method === 'GET' && !r.params.has('date'),
    );
    todayGet.flush(plan('today', []));
    await Promise.resolve();

    const put = httpMock.expectOne(
      (r) => r.url.endsWith(PLAN_URL) && r.method === 'PUT',
    );
    expectBodyHasTodo(put, 'rp-1');
    put.flush({ date: 'today', items: [], total: 1, items_removed: [] });
    await settle();

    // Item gone; that was the day's only item, so the day card is gone too.
    expect(testid('day-close-item-rp-1')).toBeNull();
    expect(testid('day-close-day-' + day)).toBeNull();
  });

  it('should drop an item via todo advance and remove it from the confrontation', async () => {
    const dates = probeDatesFromNow();
    const day = dates[0];
    await render({
      [day]: plan(day, [
        entry({ todo_id: 'dr-1', title: 'Drop me', state: 'planned' }),
        entry({ todo_id: 'keep', title: 'Keep me', state: 'planned' }),
      ]),
    });

    testid('day-close-drop-dr-1')!.dispatchEvent(new Event('click'));

    const advance = httpMock.expectOne((r) =>
      r.url.endsWith(ADVANCE_URL('dr-1')),
    );
    expect(advance.request.body).toEqual({ action: 'drop' });
    advance.flush(null);
    await settle();

    // Dropped item gone; sibling stays, day card remains.
    expect(testid('day-close-item-dr-1')).toBeNull();
    expect(testid('day-close-item-keep')).toBeTruthy();
    expect(testid('day-close-day-' + day)).toBeTruthy();
  });

  it('should leave an item visible (no-op, no HTTP)', async () => {
    const dates = probeDatesFromNow();
    const day = dates[0];
    await render({
      [day]: plan(day, [
        entry({ todo_id: 'lv-1', title: 'Leave me', state: 'planned' }),
      ]),
    });

    testid('day-close-leave-lv-1')!.dispatchEvent(new Event('click'));
    await settle();

    // No request fired; the item still confronts.
    httpMock.verify(); // no outstanding requests
    expect(testid('day-close-item-lv-1')).toBeTruthy();
  });

  it('should save the reflection as a draft musing note', async () => {
    await render({});

    const input = testid(
      'day-close-reflection-input',
    ) as HTMLInputElement | null;
    expect(input).toBeTruthy();
    input!.value = 'Slow day, but I shipped the migration.';
    input!.dispatchEvent(new Event('input'));
    fixture.detectChanges();

    testid('day-close-reflection-save')!.dispatchEvent(new Event('click'));

    const note = httpMock.expectOne((r) => r.url.endsWith(NOTES_URL));
    expect(note.request.method).toBe('POST');
    const body = note.request.body as { kind: string; body: string };
    expect(body.kind).toBe('musing');
    expect(body.body).toContain('shipped the migration');
    note.flush({
      id: 'n1',
      slug: 'day-close',
      title: body['title' as keyof typeof body] ?? 'Day close',
      kind: 'musing',
      maturity: 'seed',
      actor: 'human',
      concepts: [],
      targets: [],
      body: body.body,
      created_at: '2026-06-17T00:00:00Z',
      updated_at: '2026-06-17T00:00:00Z',
    });
    await settle();

    expect(testid('day-close-reflection-save')?.textContent).toContain('Saved');
  });
});

/**
 * The two newest probe dates (yesterday, day-before) the component will
 * request, derived the same way the component does so the spec stays
 * correct on any run date.
 */
function probeDatesFromNow(): string[] {
  const now = new Date();
  const anchor = Date.UTC(
    now.getFullYear(),
    now.getMonth(),
    now.getDate(),
    12,
  );
  const dayMs = 24 * 60 * 60 * 1000;
  const iso = (d: Date): string =>
    `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`;
  return [
    iso(new Date(anchor - 1 * dayMs)),
    iso(new Date(anchor - 2 * dayMs)),
  ];
}

/** Assert the PUT body's items include the given todo_id. */
function expectBodyHasTodo(req: TestRequest, todoId: string): void {
  const body = req.request.body as { items: { todo_id: string }[] };
  expect(body.items.some((i) => i.todo_id === todoId)).toBe(true);
}
