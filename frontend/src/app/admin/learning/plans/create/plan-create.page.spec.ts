import { vi } from 'vitest';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { of } from 'rxjs';

import { PlanCreatePageComponent } from './plan-create.page';
import { LearningService } from '../../../../core/services/learning.service';
import { PlanService } from '../../../../core/services/plan.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';

describe('PlanCreatePageComponent', () => {
  let fixture: ComponentFixture<PlanCreatePageComponent>;
  let el: HTMLElement;
  let navigateSpy: ReturnType<typeof vi.spyOn>;
  const createPlan = vi.fn();
  const getDomains = vi.fn();
  const getGoalsOverview = vi.fn();

  beforeEach(async () => {
    createPlan.mockReturnValue(of({ id: 'p_new' }));
    getDomains.mockReturnValue(of([{ slug: 'go', name: 'Go' }]));
    getGoalsOverview.mockReturnValue(of({ goals: [] }));

    TestBed.configureTestingModule({
      imports: [PlanCreatePageComponent],
      providers: [
        provideRouter([]),
        { provide: LearningService, useValue: { createPlan, getDomains } },
        { provide: PlanService, useValue: { getGoalsOverview } },
        {
          provide: AdminTopbarService,
          useValue: { set: () => undefined, reset: () => undefined },
        },
      ],
    });
    navigateSpy = vi
      .spyOn(TestBed.inject(Router), 'navigate')
      .mockResolvedValue(true);

    fixture = TestBed.createComponent(PlanCreatePageComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    el = fixture.nativeElement as HTMLElement;
  });

  afterEach(() => {
    vi.clearAllMocks();
    TestBed.resetTestingModule();
  });

  function submitBtn(): HTMLButtonElement {
    return el.querySelector(
      '[data-testid="plan-create-submit"]',
    ) as HTMLButtonElement;
  }

  async function typeTitle(value: string): Promise<void> {
    const input = el.querySelector('#plan-title') as HTMLInputElement;
    input.value = value;
    input.dispatchEvent(new Event('input'));
    await fixture.whenStable();
    fixture.detectChanges();
  }

  async function selectDomain(value: string): Promise<void> {
    const select = el.querySelector('#plan-domain') as HTMLSelectElement;
    select.value = value;
    select.dispatchEvent(new Event('change'));
    select.dispatchEvent(new Event('input'));
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('should keep submit enabled before the first submit attempt', () => {
    // Design gating: the button only disables after a failed submit.
    expect(submitBtn().disabled).toBe(false);
    expect(
      el.querySelector('[data-testid="plan-create-banner"]'),
    ).toBeNull();
  });

  it('should show the banner and not call createPlan when submitting an invalid form', async () => {
    submitBtn().click();
    await fixture.whenStable();
    fixture.detectChanges();

    expect(createPlan).not.toHaveBeenCalled();
    expect(
      el.querySelector('[data-testid="plan-create-banner"]')?.textContent,
    ).toContain('Some fields need attention');
    expect(submitBtn().disabled).toBe(true);
    // Field errors are surfaced by the submit attempt even without blur.
    expect(el.textContent).toContain('Title is required.');
    expect(el.textContent).toContain('A plan must belong to a domain.');
  });

  it('should render the live title character count', async () => {
    await typeTitle('Master graph traversal');
    expect(
      el.querySelector('[data-testid="plan-title-count"]')?.textContent,
    ).toContain('22/80');
  });

  it('should create the plan and route to its detail once title and domain are set', async () => {
    await typeTitle('  Master graph traversal  ');
    await selectDomain('go');
    expect(submitBtn().disabled).toBe(false);

    submitBtn().click();
    await fixture.whenStable();

    expect(createPlan).toHaveBeenCalledTimes(1);
    // Title is trimmed; domain is the selected slug; the goal stays
    // unlinked; target_count carries the slider default.
    expect(createPlan.mock.calls[0][0]).toMatchObject({
      title: 'Master graph traversal',
      domain: 'go',
      target_count: 9,
    });
    expect(createPlan.mock.calls[0][0].goal_id).toBeUndefined();
    expect(navigateSpy).toHaveBeenCalledWith([
      '/admin/learning/plans',
      'p_new',
    ]);
  });

  it('should send the adjusted target count when the slider moves', async () => {
    await typeTitle('Concurrency drills');
    await selectDomain('go');

    const slider = el.querySelector(
      '[data-testid="plan-target-count"]',
    ) as HTMLInputElement;
    slider.value = '14';
    slider.dispatchEvent(new Event('input'));
    await fixture.whenStable();
    fixture.detectChanges();

    expect(
      el.querySelector('[data-testid="plan-target-count-readout"]')
        ?.textContent,
    ).toContain('14 entries to scaffold');

    submitBtn().click();
    await fixture.whenStable();

    expect(createPlan.mock.calls[0][0]).toMatchObject({ target_count: 14 });
  });
});
