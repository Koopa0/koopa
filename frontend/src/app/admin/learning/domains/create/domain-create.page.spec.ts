import { vi } from 'vitest';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { of } from 'rxjs';

import { DomainCreatePageComponent } from './domain-create.page';
import { LearningService } from '../../../../core/services/learning.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';

describe('DomainCreatePageComponent', () => {
  let fixture: ComponentFixture<DomainCreatePageComponent>;
  let el: HTMLElement;
  let navigateSpy: ReturnType<typeof vi.spyOn>;
  const createDomain = vi.fn();

  beforeEach(async () => {
    createDomain.mockReturnValue(of({ slug: 'systems-design', name: 'Systems design' }));
    TestBed.configureTestingModule({
      imports: [DomainCreatePageComponent],
      providers: [
        provideRouter([]),
        { provide: LearningService, useValue: { createDomain } },
        {
          provide: AdminTopbarService,
          useValue: { set: () => undefined, reset: () => undefined },
        },
      ],
    });
    navigateSpy = vi
      .spyOn(TestBed.inject(Router), 'navigate')
      .mockResolvedValue(true);

    fixture = TestBed.createComponent(DomainCreatePageComponent);
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
      '[data-testid="domain-create-submit"]',
    ) as HTMLButtonElement;
  }

  async function type(id: string, value: string): Promise<void> {
    const input = el.querySelector(`#${id}`) as HTMLInputElement;
    input.value = value;
    input.dispatchEvent(new Event('input'));
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('should disable submit when the form is empty', () => {
    expect(submitBtn().disabled).toBe(true);
  });

  it('should keep submit disabled when the slug is not kebab-case', async () => {
    await type('domain-name', 'Systems design');
    await type('domain-slug', 'Systems Design');
    expect(submitBtn().disabled).toBe(true);
  });

  it('should create the domain and route to the list once slug and name are valid', async () => {
    await type('domain-slug', 'systems-design');
    // Name still exercises the trim on submission; the slug pattern rejects
    // surrounding whitespace so it is typed clean.
    await type('domain-name', '  Systems design  ');
    expect(submitBtn().disabled).toBe(false);

    submitBtn().click();
    await fixture.whenStable();

    expect(createDomain).toHaveBeenCalledTimes(1);
    // Slug and name are trimmed before submission.
    expect(createDomain.mock.calls[0][0]).toMatchObject({
      slug: 'systems-design',
      name: 'Systems design',
    });
    expect(navigateSpy).toHaveBeenCalledWith(['/admin/learning/domains']);
  });
});
