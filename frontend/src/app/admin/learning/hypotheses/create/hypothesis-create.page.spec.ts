import { vi } from 'vitest';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { of } from 'rxjs';

import { HypothesisCreatePageComponent } from './hypothesis-create.page';
import { HypothesisService } from '../../../../core/services/hypothesis.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';

describe('HypothesisCreatePageComponent', () => {
  let fixture: ComponentFixture<HypothesisCreatePageComponent>;
  let el: HTMLElement;
  let navigateSpy: ReturnType<typeof vi.spyOn>;
  const create = vi.fn();

  beforeEach(async () => {
    create.mockReturnValue(of({ id: 'h_new' }));
    TestBed.configureTestingModule({
      imports: [HypothesisCreatePageComponent],
      providers: [
        provideRouter([]),
        { provide: HypothesisService, useValue: { create } },
        {
          provide: AdminTopbarService,
          useValue: { set: () => undefined, reset: () => undefined },
        },
      ],
    });
    navigateSpy = vi
      .spyOn(TestBed.inject(Router), 'navigate')
      .mockResolvedValue(true);

    fixture = TestBed.createComponent(HypothesisCreatePageComponent);
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
      '[data-testid="hypothesis-create-submit"]',
    ) as HTMLButtonElement;
  }

  async function type(id: string, value: string): Promise<void> {
    const input = el.querySelector(`#${id}`) as HTMLTextAreaElement;
    input.value = value;
    input.dispatchEvent(new Event('input'));
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('should disable submit until both claim and invalidation are present', async () => {
    expect(submitBtn().disabled).toBe(true);

    await type('hyp-claim', 'Channels over mutexes');
    // Still missing the required invalidation condition.
    expect(submitBtn().disabled).toBe(true);

    await type('hyp-inval', 'Three drills picking the simplest primitive');
    expect(submitBtn().disabled).toBe(false);
  });

  it('should create the hypothesis and route to its profile', async () => {
    await type('hyp-claim', '  Channels over mutexes  ');
    await type('hyp-inval', 'Three clean drills');

    submitBtn().click();
    await fixture.whenStable();

    expect(create).toHaveBeenCalledTimes(1);
    expect(create.mock.calls[0][0]).toMatchObject({
      claim: 'Channels over mutexes',
      invalidation_condition: 'Three clean drills',
    });
    expect(navigateSpy).toHaveBeenCalledWith([
      '/admin/learning/hypotheses',
      'h_new',
    ]);
  });
});
