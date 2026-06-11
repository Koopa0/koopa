import { vi } from 'vitest';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ActivatedRoute, convertToParamMap, provideRouter } from '@angular/router';
import { of } from 'rxjs';

import { PlanTimelinePageComponent, reorderPayload } from './plan-timeline.page';
import { LearningService } from '../../../../core/services/learning.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type {
  PlanDetail,
  PlanEntryDetail,
} from '../../../../core/models/learning.model';

const ATTEMPT_UUID = '11111111-2222-3333-4444-555555555555';

function entry(overrides: Partial<PlanEntryDetail> = {}): PlanEntryDetail {
  return {
    plan_entry_id: 'e1',
    plan_id: 'plan-1',
    learning_target_id: 't1',
    position: 0,
    status: 'planned',
    phase: 'core',
    added_at: '2026-06-01T10:00:00Z',
    target_title: 'Two Sum',
    target_domain: 'leetcode',
    ...overrides,
  };
}

function detail(overrides: Partial<PlanDetail> = {}): PlanDetail {
  return {
    plan: {
      id: 'plan-1',
      title: 'Graph algorithms drill',
      description: 'Breadth before depth.',
      domain: 'leetcode',
      goal_id: null,
      status: 'draft',
      created_by: 'human',
      created_at: '2026-05-20T10:00:00Z',
      updated_at: '2026-06-01T10:00:00Z',
    },
    entries: [
      entry(),
      entry({
        plan_entry_id: 'e2',
        learning_target_id: 't2',
        position: 1,
        target_title: 'Course Schedule',
        phase: 'applied',
      }),
      entry({
        plan_entry_id: 'e3',
        learning_target_id: 't3',
        position: 2,
        status: 'completed',
        target_title: 'Number of Islands',
        completed_at: '2026-06-01T09:00:00Z',
        completed_by_attempt_id: ATTEMPT_UUID,
        reason: 'solved_independent on attempt #2',
      }),
    ],
    progress: { total: 3, completed: 1, skipped: 0, substituted: 0, remaining: 2 },
    ...overrides,
  };
}

describe('PlanTimelinePageComponent', () => {
  let fixture: ComponentFixture<PlanTimelinePageComponent>;
  let el: HTMLElement;
  const plan = vi.fn();
  const updatePlanStatus = vi.fn();
  const updatePlanEntry = vi.fn();
  const removePlanEntry = vi.fn();
  const reorderPlanEntries = vi.fn();

  async function setup(data: PlanDetail = detail()): Promise<void> {
    plan.mockReturnValue(of(data));
    updatePlanStatus.mockReturnValue(of(data.plan));
    updatePlanEntry.mockReturnValue(of(data.entries[0]));
    removePlanEntry.mockReturnValue(of(undefined));
    reorderPlanEntries.mockReturnValue(of(data));

    TestBed.configureTestingModule({
      imports: [PlanTimelinePageComponent],
      providers: [
        provideRouter([]),
        {
          provide: LearningService,
          useValue: {
            plan,
            updatePlanStatus,
            updatePlanEntry,
            removePlanEntry,
            reorderPlanEntries,
          },
        },
        {
          provide: ActivatedRoute,
          useValue: { paramMap: of(convertToParamMap({ id: 'plan-1' })) },
        },
        {
          provide: AdminTopbarService,
          useValue: { set: () => undefined, reset: () => undefined },
        },
      ],
    });

    fixture = TestBed.createComponent(PlanTimelinePageComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    el = fixture.nativeElement as HTMLElement;
  }

  afterEach(() => {
    vi.clearAllMocks();
    TestBed.resetTestingModule();
  });

  function byTestId<T extends HTMLElement>(id: string): T | null {
    return el.querySelector(`[data-testid="${id}"]`) as T | null;
  }

  async function settle(): Promise<void> {
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('should render ordered entries with phase and status badges', async () => {
    await setup();

    expect(byTestId('plan-detail')).not.toBeNull();
    expect(el.textContent).toContain('Two Sum');
    expect(byTestId('plan-entry-phase-0')?.textContent).toContain('core');
    expect(byTestId('plan-entry-status-0')?.textContent).toContain('planned');
    expect(byTestId('plan-entry-status-2')?.textContent).toContain(
      'completed',
    );
    // Completed entries surface the audit trail.
    expect(el.textContent).toContain('via attempt 11111111');
    expect(el.textContent).toContain('solved_independent on attempt #2');
  });

  it('should render the five-field progress legend', async () => {
    await setup();

    const legend = byTestId('plan-progress-legend')?.textContent ?? '';
    expect(legend).toContain('1 completed');
    expect(legend).toContain('0 substituted');
    expect(legend).toContain('0 skipped');
    expect(legend).toContain('2 remaining');
    expect(legend).toContain('3 total');
  });

  it('should activate a draft plan through the status endpoint', async () => {
    await setup();

    expect(byTestId('plan-status-badge')?.textContent).toContain('draft');
    byTestId<HTMLButtonElement>('plan-status-active')?.click();
    await settle();

    expect(updatePlanStatus).toHaveBeenCalledWith('plan-1', 'active');
  });

  it('should offer pause, complete and abandon for an active plan', async () => {
    const data = detail();
    await setup({ ...data, plan: { ...data.plan, status: 'active' } });

    expect(byTestId('plan-status-paused')).not.toBeNull();
    expect(byTestId('plan-status-completed')).not.toBeNull();
    expect(byTestId('plan-status-abandoned')).not.toBeNull();
    expect(byTestId('plan-status-active')).toBeNull();
  });

  it('should remove an entry while the plan is a draft', async () => {
    await setup();

    byTestId<HTMLButtonElement>('plan-entry-remove-0')?.click();
    await settle();

    expect(removePlanEntry).toHaveBeenCalledWith('plan-1', 'e1');
  });

  it('should hide the remove affordance when the plan is not a draft', async () => {
    const data = detail();
    await setup({ ...data, plan: { ...data.plan, status: 'active' } });

    expect(byTestId('plan-entry-remove-0')).toBeNull();
  });

  it('should gate completion on the justifying attempt id and reason', async () => {
    await setup();

    byTestId<HTMLButtonElement>('plan-entry-complete-0')?.click();
    await settle();

    const confirm = byTestId<HTMLButtonElement>('plan-complete-confirm');
    expect(byTestId('plan-complete-modal')).not.toBeNull();
    expect(confirm?.disabled).toBe(true);

    // Confirming while incomplete must not fire the request.
    confirm?.click();
    await settle();
    expect(updatePlanEntry).not.toHaveBeenCalled();

    const attemptInput = byTestId<HTMLInputElement>(
      'plan-complete-attempt-id',
    )!;
    attemptInput.value = ATTEMPT_UUID;
    attemptInput.dispatchEvent(new Event('input'));
    const reasonArea = byTestId<HTMLTextAreaElement>('plan-complete-reason')!;
    reasonArea.value = 'solved_independent, 8 min, clean implementation';
    reasonArea.dispatchEvent(new Event('input'));
    await settle();

    expect(
      byTestId<HTMLButtonElement>('plan-complete-confirm')?.disabled,
    ).toBe(false);
    byTestId<HTMLButtonElement>('plan-complete-confirm')?.click();
    await settle();

    expect(updatePlanEntry).toHaveBeenCalledWith('plan-1', 'e1', {
      status: 'completed',
      completed_by_attempt_id: ATTEMPT_UUID,
      reason: 'solved_independent, 8 min, clean implementation',
    });
  });

  it('should reject a non-UUID attempt id in the audit gate', async () => {
    await setup();

    byTestId<HTMLButtonElement>('plan-entry-complete-0')?.click();
    await settle();

    const attemptInput = byTestId<HTMLInputElement>(
      'plan-complete-attempt-id',
    )!;
    attemptInput.value = 'not-a-uuid';
    attemptInput.dispatchEvent(new Event('input'));
    const reasonArea = byTestId<HTMLTextAreaElement>('plan-complete-reason')!;
    reasonArea.value = 'good enough';
    reasonArea.dispatchEvent(new Event('input'));
    await settle();

    expect(
      byTestId<HTMLButtonElement>('plan-complete-confirm')?.disabled,
    ).toBe(true);
    expect(el.textContent).toContain("Must be the attempt's UUID.");
  });

  it('should skip an entry as a plain transition', async () => {
    await setup();

    byTestId<HTMLButtonElement>('plan-entry-skip-0')?.click();
    await settle();

    expect(updatePlanEntry).toHaveBeenCalledWith('plan-1', 'e1', {
      status: 'skipped',
    });
  });

  it('should require picking the substituting entry before confirming', async () => {
    await setup();

    byTestId<HTMLButtonElement>('plan-entry-substitute-0')?.click();
    await settle();

    expect(byTestId('plan-substitute-modal')).not.toBeNull();
    const confirm = byTestId<HTMLButtonElement>('plan-substitute-confirm');
    expect(confirm?.disabled).toBe(true);
    // The entry being substituted is not offered as its own substitute.
    expect(
      byTestId('plan-substitute-modal')?.textContent,
    ).not.toContain('Two Sum');

    byTestId<HTMLButtonElement>('plan-substitute-option-0')?.click();
    await settle();

    expect(
      byTestId<HTMLButtonElement>('plan-substitute-confirm')?.disabled,
    ).toBe(false);
    byTestId<HTMLButtonElement>('plan-substitute-confirm')?.click();
    await settle();

    expect(updatePlanEntry).toHaveBeenCalledWith('plan-1', 'e1', {
      status: 'substituted',
      substituted_by: 'e2',
    });
  });
});

describe('reorderPayload', () => {
  it('should rewrite every position to the array order', () => {
    const entries = [
      entry({ plan_entry_id: 'b', position: 5 }),
      entry({ plan_entry_id: 'a', position: 0 }),
      entry({ plan_entry_id: 'c', position: 2 }),
    ];

    expect(reorderPayload(entries)).toEqual([
      { plan_entry_id: 'b', position: 0 },
      { plan_entry_id: 'a', position: 1 },
      { plan_entry_id: 'c', position: 2 },
    ]);
  });
});
