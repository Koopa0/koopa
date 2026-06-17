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
  TargetAttempt,
} from '../../../../core/models/learning.model';

const ATTEMPT_UUID = '11111111-2222-3333-4444-555555555555';
const TARGET_UUID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';

function attempt(overrides: Partial<TargetAttempt> = {}): TargetAttempt {
  return {
    id: ATTEMPT_UUID,
    learning_target_id: 't1',
    session_id: 's1',
    attempt_number: 2,
    paradigm: 'cold',
    outcome: 'solved_independent',
    duration_minutes: 8,
    attempted_at: '2026-06-01T09:00:00Z',
    target_title: 'Two Sum',
    ...overrides,
  };
}

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
      goal_id: 'g-1',
      status: 'draft',
      created_by: 'human',
      created_at: '2026-05-20T10:00:00Z',
      updated_at: '2026-06-01T10:00:00Z',
    },
    goal_name: 'Crack the FAANG interview',
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
  const targetAttempts = vi.fn();
  const addPlanEntries = vi.fn();

  async function setup(
    data: PlanDetail = detail(),
    attempts: TargetAttempt[] = [attempt()],
  ): Promise<void> {
    plan.mockReturnValue(of(data));
    updatePlanStatus.mockReturnValue(of(data.plan));
    updatePlanEntry.mockReturnValue(of(data.entries[0]));
    removePlanEntry.mockReturnValue(of(undefined));
    reorderPlanEntries.mockReturnValue(of(data));
    targetAttempts.mockReturnValue(of(attempts));
    addPlanEntries.mockReturnValue(of([]));

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
            targetAttempts,
            addPlanEntries,
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

  it('should show the linked goal title in the meta strip, not the goal id', async () => {
    await setup();

    const goalMeta = byTestId('plan-goal')?.textContent ?? '';
    expect(goalMeta).toContain('Crack the FAANG interview');
    expect(goalMeta).not.toContain('g-1');
  });

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

  it('should gate completion on picking a justifying attempt and a reason', async () => {
    await setup();

    byTestId<HTMLButtonElement>('plan-entry-complete-0')?.click();
    await settle();

    const confirm = byTestId<HTMLButtonElement>('plan-complete-confirm');
    expect(byTestId('plan-complete-modal')).not.toBeNull();
    expect(confirm?.disabled).toBe(true);
    // The picker fetched attempts for the entry's target.
    expect(targetAttempts).toHaveBeenCalledWith('t1');
    // Each option shows its outcome + date so the attempt is recognizable.
    expect(byTestId('plan-complete-attempt-0')?.textContent).toContain(
      'solved_independent',
    );

    // Confirming while incomplete must not fire the request.
    confirm?.click();
    await settle();
    expect(updatePlanEntry).not.toHaveBeenCalled();

    byTestId<HTMLButtonElement>('plan-complete-attempt-0')?.click();
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

  it('should show the empty state when the entry target has no attempts', async () => {
    await setup(detail(), []);

    byTestId<HTMLButtonElement>('plan-entry-complete-0')?.click();
    await settle();

    expect(byTestId('plan-complete-attempts-empty')).not.toBeNull();
    expect(byTestId('plan-complete-attempt-0')).toBeNull();
    expect(
      byTestId<HTMLButtonElement>('plan-complete-confirm')?.disabled,
    ).toBe(true);
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

  it('should gate the add-entry submit on a valid target id and kebab-case phase', async () => {
    await setup();

    expect(byTestId('plan-add-entry')).not.toBeNull();
    byTestId<HTMLButtonElement>('plan-add-entry')?.click();
    await settle();

    const confirm = byTestId<HTMLButtonElement>('plan-add-confirm');
    expect(byTestId('plan-add-modal')).not.toBeNull();
    // No target id yet → submit disabled, no request.
    expect(confirm?.disabled).toBe(true);
    confirm?.click();
    await settle();
    expect(addPlanEntries).not.toHaveBeenCalled();

    // A non-UUID target id surfaces the inline error and keeps submit disabled.
    const idInput = byTestId<HTMLInputElement>('plan-add-target-id')!;
    idInput.value = 'not-a-uuid';
    idInput.dispatchEvent(new Event('input'));
    await settle();
    expect(byTestId('plan-add-target-id-error')).not.toBeNull();
    expect(
      byTestId<HTMLButtonElement>('plan-add-confirm')?.disabled,
    ).toBe(true);

    // A valid UUID clears the error and enables submit (phase still blank).
    idInput.value = TARGET_UUID;
    idInput.dispatchEvent(new Event('input'));
    await settle();
    expect(byTestId('plan-add-target-id-error')).toBeNull();
    expect(
      byTestId<HTMLButtonElement>('plan-add-confirm')?.disabled,
    ).toBe(false);

    // A non-kebab-case phase re-disables submit and shows the phase error.
    const phaseInput = byTestId<HTMLInputElement>('plan-add-phase')!;
    phaseInput.value = 'Phase One';
    phaseInput.dispatchEvent(new Event('input'));
    await settle();
    expect(byTestId('plan-add-phase-error')).not.toBeNull();
    expect(
      byTestId<HTMLButtonElement>('plan-add-confirm')?.disabled,
    ).toBe(true);
  });

  it('should post the entry and re-render the reloaded envelope on add', async () => {
    const base = detail();
    const added = entry({
      plan_entry_id: 'e4',
      learning_target_id: TARGET_UUID,
      position: 3,
      target_title: 'Valid Parentheses',
      phase: '1-stack',
    });
    const reloaded: PlanDetail = {
      ...base,
      entries: [...base.entries, added],
      progress: { total: 4, completed: 1, skipped: 0, substituted: 0, remaining: 3 },
    };
    await setup();
    // The reload after a successful add returns the augmented envelope.
    plan.mockReturnValue(of(reloaded));

    byTestId<HTMLButtonElement>('plan-add-entry')?.click();
    await settle();

    const idInput = byTestId<HTMLInputElement>('plan-add-target-id')!;
    idInput.value = TARGET_UUID;
    idInput.dispatchEvent(new Event('input'));
    const phaseInput = byTestId<HTMLInputElement>('plan-add-phase')!;
    phaseInput.value = '1-stack';
    phaseInput.dispatchEvent(new Event('input'));
    await settle();

    byTestId<HTMLButtonElement>('plan-add-confirm')?.click();
    await settle();

    expect(addPlanEntries).toHaveBeenCalledWith('plan-1', [
      { learning_target_id: TARGET_UUID, phase: '1-stack' },
    ]);
    // Modal closed and the new entry rendered from the reloaded envelope.
    expect(byTestId('plan-add-modal')).toBeNull();
    expect(el.textContent).toContain('Valid Parentheses');
  });

  it('should hide the add affordance on a terminal plan', async () => {
    const data = detail();
    await setup({ ...data, plan: { ...data.plan, status: 'completed' } });

    expect(byTestId('plan-add-entry')).toBeNull();
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
