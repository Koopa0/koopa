import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
  TestRequest,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { HypothesesListPageComponent } from './hypotheses-list.page';
import type { Hypothesis } from '../../../../core/models/workbench.model';

const LIST_URL = '/api/admin/learning/hypotheses';

function row(overrides: Partial<Hypothesis>): Hypothesis {
  return {
    id: 'h1',
    created_by: 'planner',
    content: '',
    state: 'unverified',
    claim: 'Channels scale better than mutexes for this fan-out',
    invalidation_condition: 'Three drills still reach for a mutex first',
    observed_date: '2026-06-10',
    created_at: '2026-06-10T00:00:00Z',
    ...overrides,
  };
}

describe('HypothesesListPageComponent', () => {
  let fixture: ComponentFixture<HypothesesListPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HypothesesListPageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    try {
      httpMock
        .match((r) => r.method === 'GET' && r.url.endsWith(LIST_URL))
        .forEach((r) => r.flush({ data: [] }));
      httpMock.verify();
    } finally {
      TestBed.resetTestingModule();
    }
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function testid(id: string): HTMLElement | null {
    return el().querySelector(`[data-testid="${id}"]`);
  }

  /** Flush the single pending list GET, asserting its state param. */
  function flushList(expectedState: string | null, body: Hypothesis[]): void {
    const req: TestRequest = httpMock.expectOne(
      (r) => r.method === 'GET' && r.url.endsWith(LIST_URL),
    );
    expect(req.request.params.get('state')).toBe(expectedState);
    req.flush({ data: body });
  }

  async function settle(): Promise<void> {
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('should default to the unverified filter and render the rows', async () => {
    fixture = TestBed.createComponent(HypothesesListPageComponent);
    fixture.detectChanges();
    flushList('unverified', [row({ id: 'h1', state: 'unverified' })]);
    await settle();

    expect(testid('hypotheses-filter-state-draft')).not.toBeNull();
    expect(testid('hypotheses-list-row-0')?.textContent).toContain('mutexes');
  });

  it('should refetch with state=draft and render the draft queue when the Draft chip is selected', async () => {
    fixture = TestBed.createComponent(HypothesesListPageComponent);
    fixture.detectChanges();
    flushList('unverified', [row({ id: 'h1', state: 'unverified' })]);
    await settle();

    (testid('hypotheses-filter-state-draft') as HTMLButtonElement).click();
    fixture.detectChanges();

    flushList('draft', [
      row({ id: 'h2', state: 'draft', claim: 'Goroutine leaks come from missing ctx cancel' }),
    ]);
    await settle();

    const draftRow = testid('hypotheses-list-row-0');
    expect(draftRow?.textContent).toContain('Goroutine leaks');
    expect(draftRow?.textContent).toContain('draft');
  });
});
