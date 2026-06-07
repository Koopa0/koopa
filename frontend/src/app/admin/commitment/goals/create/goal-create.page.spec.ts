import { vi } from 'vitest';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { of } from 'rxjs';

import { GoalCreatePageComponent } from './goal-create.page';
import { PlanService } from '../../../../core/services/plan.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';

describe('GoalCreatePageComponent', () => {
  let fixture: ComponentFixture<GoalCreatePageComponent>;
  let el: HTMLElement;
  let navigateSpy: ReturnType<typeof vi.spyOn>;
  const createGoal = vi.fn();

  beforeEach(async () => {
    createGoal.mockReturnValue(of({ id: 'g_new' }));
    TestBed.configureTestingModule({
      imports: [GoalCreatePageComponent],
      providers: [
        provideRouter([]),
        { provide: PlanService, useValue: { createGoal } },
        {
          provide: AdminTopbarService,
          useValue: { set: () => undefined, reset: () => undefined },
        },
      ],
    });
    navigateSpy = vi
      .spyOn(TestBed.inject(Router), 'navigate')
      .mockResolvedValue(true);

    fixture = TestBed.createComponent(GoalCreatePageComponent);
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
      '[data-testid="goal-create-submit"]',
    ) as HTMLButtonElement;
  }

  async function typeTitle(value: string): Promise<void> {
    const input = el.querySelector('#goal-title') as HTMLInputElement;
    input.value = value;
    input.dispatchEvent(new Event('input'));
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('should disable submit when the required title is empty', () => {
    expect(submitBtn().disabled).toBe(true);
  });

  it('should enable submit and create the goal once a title is entered', async () => {
    await typeTitle('  Ship koopa v1  ');
    expect(submitBtn().disabled).toBe(false);

    submitBtn().click();
    await fixture.whenStable();

    expect(createGoal).toHaveBeenCalledTimes(1);
    // Title is trimmed before submission.
    expect(createGoal.mock.calls[0][0]).toMatchObject({ title: 'Ship koopa v1' });
    expect(navigateSpy).toHaveBeenCalledWith([
      '/admin/commitment/goals',
      'g_new',
    ]);
  });
});
