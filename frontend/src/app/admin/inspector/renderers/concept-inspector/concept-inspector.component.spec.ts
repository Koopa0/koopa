import { vi } from 'vitest';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { provideRouter } from '@angular/router';
import { ConceptInspectorComponent } from './concept-inspector.component';
import { InspectorService } from '../../inspector.service';
import type { ConceptDetail } from '../../../../core/models/workbench.model';

const baseConcept: ConceptDetail = {
  id: 'concept-1',
  slug: 'binary-search',
  name: 'Binary Search',
  domain: 'leetcode',
  kind: 'pattern',
  description: 'Search a sorted array by halving the range each step.',
  created_at: '2026-04-01T00:00:00Z',
  mastery_stage: 'developing',
  mastery_counts: {
    weakness: 1,
    improvement: 1,
    mastery: 0,
    total: 2,
  },
  recent_attempts: [
    {
      id: 'att-1',
      outcome: 'solved_independent',
      duration_minutes: 8,
      attempted_at: '2026-04-15T10:00:00Z',
      target_title: 'LC #704 Binary Search',
    },
  ],
  recent_observations: [
    {
      id: 'obs-1',
      signal_type: 'weakness',
      category: 'boundary-case-blindness',
      severity: 'moderate',
      detail: 'Off-by-one in upper bound calculation',
      created_at: '2026-04-12T09:00:00Z',
      attempted_at: '2026-04-12T09:00:00Z',
      target_title: 'LC #33',
    },
  ],
  parent_concept: null,
  low_confidence_count: 0,
  low_confidence_observations: [],
  targets_exercising_count: 4,
};

describe('ConceptInspectorComponent', () => {
  let fixture: ComponentFixture<ConceptInspectorComponent>;
  let httpMock: HttpTestingController;
  let inspector: InspectorService;

  function setupFixture(): void {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideNoopAnimations(),
        provideRouter([]),
      ],
    });
    fixture = TestBed.createComponent(ConceptInspectorComponent);
    httpMock = TestBed.inject(HttpTestingController);
    inspector = TestBed.inject(InspectorService);
  }

  function flushAll(id: string, response: ConceptDetail | null): void {
    const reqs = httpMock.match((r) =>
      r.url.includes(`/api/admin/learning/concepts/${id}`),
    );
    expect(reqs.length).toBeGreaterThan(0);
    for (const r of reqs) {
      if (response === null) {
        r.flush(null, { status: 500, statusText: 'Internal Server Error' });
      } else {
        r.flush({ data: response });
      }
    }
  }

  async function loadAndSettle(c: ConceptDetail | null): Promise<void> {
    fixture.componentRef.setInput('id', baseConcept.id);
    fixture.detectChanges();
    flushAll(baseConcept.id, c);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('should render name and subtitle (kind · domain · stage)', async () => {
    setupFixture();
    await loadAndSettle(baseConcept);

    const el = fixture.nativeElement as HTMLElement;
    expect(
      el.querySelector('[data-testid="concept-name"]')?.textContent,
    ).toContain('Binary Search');
    const subtitle = el.querySelector('[data-testid="concept-subtitle"]');
    expect(subtitle?.textContent).toContain('pattern');
    expect(subtitle?.textContent).toContain('leetcode');
    expect(subtitle?.textContent).toContain('developing');
    const stage = el.querySelector('[data-testid="concept-stage"]');
    expect(stage?.className).toContain('text-zinc-400');
  });

  it('should color stage text amber when struggling', async () => {
    setupFixture();
    await loadAndSettle({ ...baseConcept, mastery_stage: 'struggling' });
    const stage = fixture.nativeElement.querySelector(
      '[data-testid="concept-stage"]',
    );
    expect(stage?.className).toContain('text-amber-400');
  });

  it('should render mastery counts as plain text (no stacked bar)', async () => {
    setupFixture();
    await loadAndSettle(baseConcept);

    const counts = fixture.nativeElement.querySelector(
      '[data-testid="concept-mastery-counts"]',
    );
    expect(counts?.textContent).toContain('1 weakness');
    expect(counts?.textContent).toContain('1 improvement');
    expect(counts?.textContent).toContain('0 mastery');
    // Must NOT contain a stacked bar SVG/div
    expect(
      fixture.nativeElement.querySelector('[role="progressbar"]'),
    ).toBeFalsy();
  });

  it('should render recent attempts with outcome icon', async () => {
    setupFixture();
    await loadAndSettle(baseConcept);

    const attempts = fixture.nativeElement.querySelector(
      '[data-testid="concept-attempts-list"]',
    );
    expect(attempts?.textContent).toContain('LC #704 Binary Search');
    expect(attempts?.textContent).toContain('8min');
  });

  it('should render observations grouped by signal_type with colored TEXT labels', async () => {
    setupFixture();
    await loadAndSettle(baseConcept);

    const weakGroup = fixture.nativeElement.querySelector(
      '[data-testid="obs-group-weakness"]',
    );
    expect(weakGroup?.textContent).toContain('Weaknesses');
    expect(weakGroup?.textContent).toContain('boundary-case-blindness');
    expect(weakGroup?.textContent).toContain('moderate');
    // Heading uses colored text
    const heading = weakGroup?.querySelector('h4');
    expect(heading?.className).toContain('text-red-400');
  });

  it('should render <details> for low-confidence observations only when count > 0', async () => {
    setupFixture();
    await loadAndSettle({
      ...baseConcept,
      low_confidence_count: 2,
      low_confidence_observations: [
        {
          id: 'obs-low-1',
          signal_type: 'weakness',
          category: 'state-definition',
          severity: 'minor',
          detail: 'AI inferred state confusion from solve patterns',
          created_at: '2026-04-14T10:00:00Z',
          attempted_at: null,
          target_title: 'LC #100',
        },
      ],
    });

    const details = fixture.nativeElement.querySelector(
      '[data-testid="concept-low-confidence-details"]',
    );
    expect(details).toBeTruthy();
    expect(details?.tagName.toLowerCase()).toBe('details');
    expect(details?.textContent).toContain('2 AI-inferred');
  });

  it('should NOT render low-confidence <details> when count is 0', async () => {
    setupFixture();
    await loadAndSettle(baseConcept);
    const details = fixture.nativeElement.querySelector(
      '[data-testid="concept-low-confidence-details"]',
    );
    expect(details).toBeFalsy();
  });

  it('should render parent concept link when parent_concept present', async () => {
    setupFixture();
    await loadAndSettle({
      ...baseConcept,
      parent_concept: {
        id: 'parent-1',
        slug: 'searching-algorithms',
        name: 'Searching Algorithms',
      },
    });

    const parentLink = fixture.nativeElement.querySelector(
      '[data-testid="concept-parent-link"]',
    );
    expect(parentLink?.textContent?.trim()).toBe('searching-algorithms');
  });

  it('should call inspector.open when parent concept clicked', async () => {
    setupFixture();
    const openSpy = vi.spyOn(inspector, 'open');
    await loadAndSettle({
      ...baseConcept,
      parent_concept: {
        id: 'parent-1',
        slug: 'searching-algorithms',
        name: 'Searching Algorithms',
      },
    });

    const parentLink = fixture.nativeElement.querySelector(
      '[data-testid="concept-parent-link"]',
    ) as HTMLButtonElement;
    parentLink.click();
    expect(openSpy).toHaveBeenCalledWith({ type: 'concept', id: 'parent-1' });
  });

  it('should render tail link with N targets exercising', async () => {
    setupFixture();
    await loadAndSettle(baseConcept);
    const link = fixture.nativeElement.querySelector(
      '[data-testid="concept-targets-link"]',
    );
    expect(link?.textContent).toContain('View 4 learning targets exercising');
    expect(link?.textContent).toContain('binary-search');
  });

  it('should expose copy concept SLUG button (not UUID)', async () => {
    setupFixture();
    await loadAndSettle(baseConcept);
    const copyBtn = fixture.nativeElement.querySelector(
      '[data-testid="concept-copy-slug"]',
    );
    expect(copyBtn).toBeTruthy();
    expect(copyBtn?.getAttribute('aria-label')).toBe(
      'Copy concept slug to clipboard',
    );
  });

  it('should render error state when fetch fails', async () => {
    setupFixture();
    await loadAndSettle(null);
    const alert = (fixture.nativeElement as HTMLElement).querySelector(
      '[role="alert"]',
    );
    expect(alert?.textContent).toContain('Failed');
  });
});
