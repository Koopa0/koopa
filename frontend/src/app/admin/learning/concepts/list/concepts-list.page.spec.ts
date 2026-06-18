import { vi } from 'vitest';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';

import { ConceptsListPageComponent } from './concepts-list.page';
import { LearningService } from '../../../../core/services/learning.service';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type { ConceptRow } from '../../../../core/models/learning.model';

function conceptRow(overrides: Partial<ConceptRow> = {}): ConceptRow {
  return {
    slug: 'value-semantics',
    kind: 'pattern',
    domain: 'go',
    mastery_stage: 'developing',
    mastery_counts: { weakness: 1, improvement: 2, mastery: 0 },
    obs_count: 3,
    parent_slug: null,
    ...overrides,
  };
}

describe('ConceptsListPageComponent', () => {
  let fixture: ComponentFixture<ConceptsListPageComponent>;
  let el: HTMLElement;
  const concepts = vi.fn();

  async function setup(): Promise<void> {
    TestBed.configureTestingModule({
      imports: [ConceptsListPageComponent],
      providers: [
        provideRouter([]),
        { provide: LearningService, useValue: { concepts } },
        {
          provide: AdminTopbarService,
          useValue: { set: () => undefined, reset: () => undefined },
        },
      ],
    });

    fixture = TestBed.createComponent(ConceptsListPageComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    el = fixture.nativeElement as HTMLElement;
  }

  afterEach(() => {
    vi.clearAllMocks();
    TestBed.resetTestingModule();
  });

  it('should render a row per concept', async () => {
    concepts.mockReturnValue(
      of([
        conceptRow({ slug: 'value-semantics' }),
        conceptRow({ slug: 'goroutine-leaks' }),
      ]),
    );
    await setup();

    const rows = el.querySelectorAll('[data-testid^="concepts-list-row-"]');
    expect(rows.length).toBe(2);
    expect(el.textContent).toContain('value-semantics');
    expect(el.textContent).toContain('goroutine-leaks');
  });

  it('should surface the error banner without throwing when the list read fails', async () => {
    // A plain (non-HttpErrorResponse) failure drives the generic error
    // banner, not the 404/405/501 endpoints-pending placeholder. rows() must
    // fall back to [] via the hasValue() guard rather than throw a
    // ResourceValueError.
    concepts.mockReturnValue(throwError(() => new Error('boom')));
    await setup();

    const banner = el.querySelector('[role="alert"]');
    expect(banner).not.toBeNull();
    expect(banner?.textContent).toContain("Couldn't load concepts.");
    expect(
      el.querySelector('[data-testid="concepts-endpoints-pending"]'),
    ).toBeNull();
    expect(el.querySelector('[data-testid="concepts-list-row-0"]')).toBeNull();
  });
});
