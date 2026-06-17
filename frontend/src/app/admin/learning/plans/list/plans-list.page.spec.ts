import { vi } from 'vitest';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';

import { PlansListPageComponent } from './plans-list.page';
import { LearningService } from '../../../../core/services/learning.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type { PlanSummary } from '../../../../core/models/learning.model';

function planRow(overrides: Partial<PlanSummary> = {}): PlanSummary {
  return {
    id: 'p_1',
    title: 'Graph algorithms drill',
    description: '',
    domain: 'leetcode',
    status: 'active',
    goal_id: null,
    created_by: 'human',
    entry_total: 4,
    entry_done: 1,
    created_at: '2026-05-20T10:00:00Z',
    updated_at: '2026-06-01T10:00:00Z',
    ...overrides,
  };
}

describe('PlansListPageComponent', () => {
  let fixture: ComponentFixture<PlansListPageComponent>;
  let el: HTMLElement;
  const plans = vi.fn();

  async function setup(): Promise<void> {
    TestBed.configureTestingModule({
      imports: [PlansListPageComponent],
      providers: [
        provideRouter([]),
        { provide: LearningService, useValue: { plans } },
        {
          provide: AdminTopbarService,
          useValue: { set: () => undefined, reset: () => undefined },
        },
      ],
    });

    fixture = TestBed.createComponent(PlansListPageComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    el = fixture.nativeElement as HTMLElement;
  }

  afterEach(() => {
    vi.clearAllMocks();
    TestBed.resetTestingModule();
  });

  it('should render a row per plan with the entries and progress columns', async () => {
    plans.mockReturnValue(
      of([
        planRow({
          id: 'p_1',
          title: 'Graph algorithms drill',
          entry_total: 4,
          entry_done: 1,
        }),
        planRow({ id: 'p_2', title: 'Concurrency patterns' }),
      ]),
    );
    await setup();

    const rows = el.querySelectorAll('[data-testid^="plans-list-row-"]');
    expect(rows.length).toBe(2);
    expect(el.textContent).toContain('Graph algorithms drill');
    expect(el.textContent).toContain('Concurrency patterns');
    expect(el.querySelector('[data-testid="plans-count"]')?.textContent).toContain(
      '2',
    );
    // Entries/Progress columns reflect the per-plan counts (1/4 → 25%).
    expect(
      el.querySelector('[data-testid="plans-list-entries-0"]')?.textContent,
    ).toContain('1/4');
    expect(
      el.querySelector('[data-testid="plans-list-progress-0"]')?.textContent,
    ).toContain('25%');
  });

  it('should show the empty state when no plans exist', async () => {
    plans.mockReturnValue(of([]));
    await setup();

    expect(el.querySelector('[data-testid="plans-list-table"]')).toBeNull();
    expect(el.textContent).toContain('No plans yet');
    expect(el.textContent).toContain(
      'Create a plan to sequence your learning targets.',
    );
  });
});
