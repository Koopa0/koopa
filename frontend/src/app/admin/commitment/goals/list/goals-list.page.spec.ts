import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';
import { vi } from 'vitest';

import { GoalsListPageComponent } from './goals-list.page';
import type { GoalSummary } from '../../../../core/models/admin.model';

const GOALS_URL = '/api/admin/commitment/goals';

/** A rich list row — Goal fields + area_name + singular milestone counts. */
function row(overrides: Partial<GoalSummary>): GoalSummary {
  return {
    id: 'g1',
    title: 'Ship koopa v1',
    description: '',
    status: 'in_progress',
    area_name: 'Build',
    milestone_total: 4,
    milestone_done: 1,
    quarter: '2026-Q3',
    deadline: '2026-09-30',
    created_at: '2026-05-01T00:00:00Z',
    updated_at: '2026-06-01T00:00:00Z',
    ...overrides,
  };
}

const ROWS: GoalSummary[] = [
  row({ id: 'g1', title: 'Ship koopa v1', status: 'in_progress' }),
  row({ id: 'g2', title: 'Draft the GDE story', status: 'not_started' }),
  row({
    id: 'g3',
    title: 'Old archived goal',
    status: 'done',
    area_name: '',
    milestone_total: 2,
    milestone_done: 2,
  }),
];

describe('GoalsListPageComponent', () => {
  let fixture: ComponentFixture<GoalsListPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [GoalsListPageComponent],
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

  /** Flush the single list GET; rxResource resolves on a macrotask. */
  async function render(body: GoalSummary[]): Promise<void> {
    fixture = TestBed.createComponent(GoalsListPageComponent);
    fixture.detectChanges();
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();
    httpMock.expectOne((r) => r.url.endsWith(GOALS_URL)).flush({ data: body });
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('should request the unfiltered goals endpoint exactly once (no ?status=)', async () => {
    fixture = TestBed.createComponent(GoalsListPageComponent);
    fixture.detectChanges();
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();

    const req = httpMock.expectOne((r) => r.url.endsWith(GOALS_URL));
    expect(req.request.method).toBe('GET');
    expect(req.request.params.has('status')).toBe(false);
    req.flush({ data: ROWS });
    await fixture.whenStable();
    fixture.detectChanges();
  });

  it('should render area_name and singular milestone counts from the rich wire', async () => {
    await render(ROWS);

    const firstRow = testid('goals-list-row-0');
    expect(firstRow?.textContent).toContain('Ship koopa v1');
    expect(firstRow?.textContent).toContain('Build');
    // milestone_done / milestone_total — singular fields.
    expect(firstRow?.textContent).toContain('1 / 4');
  });

  it('should default to the active filter (in_progress + not_started)', async () => {
    await render(ROWS);

    // Active hides the done row; g1 + g2 remain.
    expect(testid('goals-count')?.textContent).toContain('2 goals');
    expect(testid('goals-list-row-0')?.textContent).toContain('Ship koopa v1');
    expect(testid('goals-list-row-1')?.textContent).toContain(
      'Draft the GDE story',
    );
    expect(el().textContent).not.toContain('Old archived goal');
  });

  it('should reveal every status when the All chip is selected (client-side, no refetch)', async () => {
    await render(ROWS);

    (testid('goals-filter-status-all') as HTMLButtonElement).click();
    fixture.detectChanges();

    expect(testid('goals-count')?.textContent).toContain('3 goals');
    expect(el().textContent).toContain('Old archived goal');
    // No second HTTP request — filtering is pure client-side.
    httpMock.expectNone((r) => r.url.endsWith(GOALS_URL));
  });

  it('should filter to a single status when its chip is selected', async () => {
    await render(ROWS);

    (testid('goals-filter-status-done') as HTMLButtonElement).click();
    fixture.detectChanges();

    expect(testid('goals-count')?.textContent).toContain('1 goal');
    expect(el().textContent).toContain('Old archived goal');
    expect(el().textContent).not.toContain('Ship koopa v1');
  });

  it('should show a dash for a goal with no area', async () => {
    await render([row({ id: 'g3', status: 'done', area_name: '' })]);
    (testid('goals-filter-status-all') as HTMLButtonElement).click();
    fixture.detectChanges();

    expect(testid('goals-list-row-0')?.textContent).toContain('—');
  });

  it('should navigate to the goal detail when a row is opened', async () => {
    await render(ROWS);
    const navigateSpy = vi
      .spyOn(TestBed.inject(Router), 'navigate')
      .mockResolvedValue(true);

    (testid('goals-list-row-0') as HTMLElement).click();

    expect(navigateSpy).toHaveBeenCalledWith([
      '/admin/commitment/goals',
      'g1',
    ]);
  });

  it('should surface the error banner when the list read fails', async () => {
    fixture = TestBed.createComponent(GoalsListPageComponent);
    fixture.detectChanges();
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.url.endsWith(GOALS_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Server Error' },
      );
    await fixture.whenStable();
    fixture.detectChanges();

    expect(testid('goals-list-error')).not.toBeNull();
  });
});
