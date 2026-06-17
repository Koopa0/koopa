import { vi } from 'vitest';
import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';

import { NextUpCardComponent } from './next-up-card.component';

const NEXT_TARGET_URL = '/api/admin/learning/next-target';
const SESSIONS_URL = '/api/admin/learning/sessions';

describe('NextUpCardComponent', () => {
  let fixture: ComponentFixture<NextUpCardComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(NextUpCardComponent);
    fixture.detectChanges();
  });

  afterEach(() => {
    httpMock.verify();
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  /** Lets the resource loader issue its request, then renders. */
  async function settle(): Promise<void> {
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  function flushTarget(body: Record<string, unknown>): void {
    httpMock
      .expectOne((r) => r.url.endsWith(NEXT_TARGET_URL))
      .flush({ data: body });
  }

  it('should render the recommended concept and reason, with a Start session action', async () => {
    await settle();
    flushTarget({
      empty: false,
      concept_slug: 'two-pointer',
      concept_name: 'Two Pointer',
      domain: 'leetcode',
      mastery_stage: 'struggling',
      severity: 'critical',
      days_since_practice: 3,
      reason: 'Two Pointer — a critical weakness, last practiced 3 days ago',
    });
    await settle();

    const card = el().querySelector('[data-testid="next-up-target"]');
    expect(card?.textContent).toContain('Two Pointer');
    expect(card?.textContent).toContain('last practiced 3 days ago');
    expect(
      el().querySelector('[data-testid="next-up-start"]'),
    ).toBeTruthy();
  });

  it('should show the empty state with its reason and no Start action', async () => {
    await settle();
    flushTarget({
      empty: true,
      reason: 'no concepts need practice in the last 30 days — nothing yet',
    });
    await settle();

    expect(
      el().querySelector('[data-testid="next-up-empty"]')?.textContent,
    ).toContain('nothing yet');
    expect(el().querySelector('[data-testid="next-up-start"]')).toBeNull();
  });

  it('should start a review session in the recommended domain and navigate to it', async () => {
    const navigate = vi
      .spyOn(TestBed.inject(Router), 'navigate')
      .mockResolvedValue(true);

    await settle();
    flushTarget({
      empty: false,
      concept_slug: 'two-pointer',
      concept_name: 'Two Pointer',
      domain: 'leetcode',
      reason: 'practice this',
    });
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="next-up-start"]')
      ?.click();

    const req = httpMock.expectOne((r) => r.url.endsWith(SESSIONS_URL));
    expect(req.request.body).toEqual({ domain: 'leetcode', mode: 'review' });
    req.flush({ data: { id: 'sess-1' } });
    await settle();

    expect(navigate).toHaveBeenCalledWith([
      '/admin/learning/sessions',
      'sess-1',
    ]);
  });

  it('should re-enable the action and not navigate when a session is already active', async () => {
    const navigate = vi
      .spyOn(TestBed.inject(Router), 'navigate')
      .mockResolvedValue(true);

    await settle();
    flushTarget({
      empty: false,
      concept_name: 'Two Pointer',
      domain: 'leetcode',
      reason: 'practice this',
    });
    await settle();

    el()
      .querySelector<HTMLButtonElement>('[data-testid="next-up-start"]')
      ?.click();
    httpMock
      .expectOne((r) => r.url.endsWith(SESSIONS_URL))
      .flush(
        { error: { code: 'CONFLICT', message: 'a session is already active' } },
        { status: 409, statusText: 'Conflict' },
      );
    await settle();

    expect(navigate).not.toHaveBeenCalled();
    const btn = el().querySelector<HTMLButtonElement>(
      '[data-testid="next-up-start"]',
    );
    expect(btn?.disabled).toBe(false);
  });

  it('should show an error state with retry when the read fails', async () => {
    await settle();
    httpMock
      .expectOne((r) => r.url.endsWith(NEXT_TARGET_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Internal Server Error' },
      );
    await settle();

    expect(el().querySelector('[data-testid="next-up-error"]')).toBeTruthy();
  });
});
