import { vi } from 'vitest';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import {
  ActivatedRoute,
  convertToParamMap,
  provideRouter,
  Router,
} from '@angular/router';
import { of } from 'rxjs';

import { HypothesisProfilePageComponent } from './hypothesis-profile.page';
import { NotificationService } from '../../../../core/services/notification.service';
import type { Hypothesis } from '../../../../core/models/workbench.model';

const HYP_URL = '/api/admin/learning/hypotheses/h1';
const LINEAGE_URL = '/api/admin/learning/hypotheses/h1/lineage';
const ENDORSE_URL = '/api/admin/learning/hypotheses/h1/endorse';
const EVIDENCE_URL = '/api/admin/learning/hypotheses/h1/evidence';

function hyp(overrides?: Partial<Hypothesis>): Hypothesis {
  return {
    id: 'h1',
    created_by: 'planner',
    content: '',
    state: 'draft',
    claim: 'Channels scale better than mutexes for this fan-out',
    invalidation_condition: 'Three drills still reach for a mutex first',
    observed_date: '2026-06-10',
    created_at: '2026-06-10T00:00:00Z',
    ...overrides,
  };
}

describe('HypothesisProfilePageComponent', () => {
  let fixture: ComponentFixture<HypothesisProfilePageComponent>;
  let httpMock: HttpTestingController;
  let navigateSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HypothesisProfilePageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        {
          provide: ActivatedRoute,
          useValue: { paramMap: of(convertToParamMap({ id: 'h1' })) },
        },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    navigateSpy = vi
      .spyOn(TestBed.inject(Router), 'navigate')
      .mockResolvedValue(true);
  });

  afterEach(() => {
    try {
      // Both resources may re-fire during stabilization; drain stragglers.
      flushHyp(hyp());
      flushLineage(hyp());
      httpMock.verify();
    } finally {
      TestBed.resetTestingModule();
      vi.clearAllMocks();
    }
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function testid(id: string): HTMLElement | null {
    return el().querySelector(`[data-testid="${id}"]`);
  }

  /** Flush every pending hypothesis GET; returns how many were open. */
  function flushHyp(body: Hypothesis): number {
    const reqs = httpMock.match(
      (r) => r.method === 'GET' && r.url.endsWith(HYP_URL),
    );
    for (const r of reqs) r.flush({ data: body });
    return reqs.length;
  }

  /** Drain the lineage read (fires alongside the hypothesis read). */
  function flushLineage(body: Hypothesis): void {
    httpMock
      .match((r) => r.method === 'GET' && r.url.endsWith(LINEAGE_URL))
      .forEach((r) =>
        r.flush({ data: { hypothesis: body, observations: [], evidence_log: [] } }),
      );
  }

  async function settle(): Promise<void> {
    await fixture.whenStable();
    fixture.detectChanges();
  }

  async function render(body: Hypothesis): Promise<void> {
    fixture = TestBed.createComponent(HypothesisProfilePageComponent);
    fixture.detectChanges();
    expect(flushHyp(body)).toBeGreaterThan(0);
    flushLineage(body);
    await settle();
    flushHyp(body);
    flushLineage(body);
    fixture.detectChanges();
  }

  function toastMessages(): string[] {
    return TestBed.inject(NotificationService)
      .notifications()
      .map((n) => n.message);
  }

  it('should surface the error state without throwing when the hypothesis read fails', async () => {
    fixture = TestBed.createComponent(HypothesisProfilePageComponent);
    fixture.detectChanges();

    // Fail the primary hypothesis read with a 500. hypothesis() must fall
    // back to undefined via the hasValue() guard rather than throw a
    // ResourceValueError, and the error panel must render.
    const reqs = httpMock.match(
      (r) => r.method === 'GET' && r.url.endsWith(HYP_URL),
    );
    expect(reqs.length).toBeGreaterThan(0);
    for (const r of reqs) {
      r.flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Server Error' },
      );
    }
    // The lineage read fires alongside; drain it so verify() stays clean.
    flushLineage(hyp());
    await settle();

    expect(testid('hypothesis-error')).not.toBeNull();
  });

  it('should show only Endorse + Delete for a draft, hiding investigation actions', async () => {
    await render(hyp({ state: 'draft' }));

    expect(testid('hypothesis-action-endorse')).not.toBeNull();
    expect(testid('hypothesis-action-delete')).not.toBeNull();
    // A draft is inert — no evidence/verify/invalidate/archive yet.
    expect(testid('hypothesis-action-add-evidence')).toBeNull();
    expect(testid('hypothesis-action-verify')).toBeNull();
    expect(testid('hypothesis-action-invalidate')).toBeNull();
    expect(testid('hypothesis-action-archive')).toBeNull();
  });

  it('should show the investigation actions and hide draft actions for an unverified hypothesis', async () => {
    await render(hyp({ state: 'unverified' }));

    expect(testid('hypothesis-action-verify')).not.toBeNull();
    expect(testid('hypothesis-action-invalidate')).not.toBeNull();
    expect(testid('hypothesis-action-archive')).not.toBeNull();
    expect(testid('hypothesis-action-add-evidence')).not.toBeNull();
    expect(testid('hypothesis-action-endorse')).toBeNull();
    expect(testid('hypothesis-action-delete')).toBeNull();
  });

  it('should POST endorse and surface the promoted state after reload', async () => {
    await render(hyp({ state: 'draft' }));

    (testid('hypothesis-action-endorse') as HTMLButtonElement).click();
    fixture.detectChanges();

    const post = httpMock.expectOne(
      (r) => r.method === 'POST' && r.url.endsWith(ENDORSE_URL),
    );
    expect(post.request.body).toEqual({});
    post.flush({ data: hyp({ state: 'unverified' }) });
    fixture.detectChanges();

    // The page reloads the hypothesis + lineage after endorsing.
    expect(flushHyp(hyp({ state: 'unverified' }))).toBeGreaterThan(0);
    flushLineage(hyp({ state: 'unverified' }));
    await settle();
    flushHyp(hyp({ state: 'unverified' }));
    flushLineage(hyp({ state: 'unverified' }));
    fixture.detectChanges();

    expect(toastMessages()).toContain('Endorsed — now unverified.');
    // Now unverified: the draft actions are gone, verify is available.
    expect(testid('hypothesis-action-endorse')).toBeNull();
    expect(testid('hypothesis-action-verify')).not.toBeNull();
  });

  it('should require a confirm before deleting a draft, then DELETE and route to the list', async () => {
    await render(hyp({ state: 'draft' }));

    (testid('hypothesis-action-delete') as HTMLButtonElement).click();
    fixture.detectChanges();
    // First click only reveals the confirm — no request yet.
    httpMock.expectNone((r) => r.method === 'DELETE' && r.url.endsWith(HYP_URL));
    expect(testid('hypothesis-delete-confirm')).not.toBeNull();

    (testid('hypothesis-delete-confirm') as HTMLButtonElement).click();
    fixture.detectChanges();

    const del = httpMock.expectOne(
      (r) => r.method === 'DELETE' && r.url.endsWith(HYP_URL),
    );
    del.flush(null, { status: 204, statusText: 'No Content' });
    fixture.detectChanges();

    expect(navigateSpy).toHaveBeenCalledWith(['/admin/learning/hypotheses']);
    expect(toastMessages()).toContain('Draft deleted.');
  });

  it('should not DELETE when the delete confirm is dismissed', async () => {
    await render(hyp({ state: 'draft' }));

    (testid('hypothesis-action-delete') as HTMLButtonElement).click();
    fixture.detectChanges();
    (testid('hypothesis-delete-cancel') as HTMLButtonElement).click();
    fixture.detectChanges();

    httpMock.expectNone((r) => r.method === 'DELETE' && r.url.endsWith(HYP_URL));
    expect(testid('hypothesis-action-delete')).not.toBeNull();
  });

  it('should POST evidence wrapped in an { evidence } envelope (handler requires it)', async () => {
    await render(hyp({ state: 'unverified' }));

    (testid('hypothesis-action-add-evidence') as HTMLButtonElement).click();
    fixture.detectChanges();

    const body = testid('hypothesis-evidence-body') as HTMLTextAreaElement;
    body.value = 'Three drills all reached for a mutex first';
    body.dispatchEvent(new Event('input'));
    fixture.detectChanges();

    (testid('hypothesis-evidence-submit') as HTMLButtonElement).click();
    fixture.detectChanges();

    const post = httpMock.expectOne(
      (r) => r.method === 'POST' && r.url.endsWith(EVIDENCE_URL),
    );
    // The handler 400s unless the body is nested under `evidence`.
    expect(post.request.body).toEqual({
      evidence: {
        type: 'supporting',
        body: 'Three drills all reached for a mutex first',
      },
    });
    post.flush({ data: hyp({ state: 'unverified' }) });
    fixture.detectChanges();

    expect(flushHyp(hyp({ state: 'unverified' }))).toBeGreaterThan(0);
    flushLineage(hyp({ state: 'unverified' }));
    await settle();
    flushHyp(hyp({ state: 'unverified' }));
    flushLineage(hyp({ state: 'unverified' }));
    fixture.detectChanges();
  });
});
