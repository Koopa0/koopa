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

  it('should disable submit when the title is empty', () => {
    expect(submitBtn().disabled).toBe(true);
  });

  it('should keep submit disabled when a domain is not selected', async () => {
    await typeTitle('Master graph traversal');
    expect(submitBtn().disabled).toBe(true);
  });

  it('should create the plan and route to its detail once title and domain are set', async () => {
    await typeTitle('  Master graph traversal  ');
    await selectDomain('go');
    expect(submitBtn().disabled).toBe(false);

    submitBtn().click();
    await fixture.whenStable();

    expect(createPlan).toHaveBeenCalledTimes(1);
    // Title is trimmed; domain is the selected slug; optionals are omitted.
    expect(createPlan.mock.calls[0][0]).toMatchObject({
      title: 'Master graph traversal',
      domain: 'go',
    });
    expect(navigateSpy).toHaveBeenCalledWith([
      '/admin/learning/plans',
      'p_new',
    ]);
  });
});
