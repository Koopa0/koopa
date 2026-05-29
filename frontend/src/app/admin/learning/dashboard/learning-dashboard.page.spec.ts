import { ComponentFixture, TestBed } from '@angular/core/testing';
import { HttpErrorResponse } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';

import { LearningDashboardPageComponent } from './learning-dashboard.page';
import { LearningService } from '../../../core/services/learning.service';
import { NotificationService } from '../../../core/services/notification.service';
import { AdminTopbarService } from '../../admin-layout/admin-topbar.service';
import type { DashboardOverview } from '../../../core/models/learning.model';

// Product-truth guard for the Learning dashboard (FSRS review surface).
// `/api/admin/learning/dashboard` is a live backend route, so the page
// must never tell the operator the endpoint "is not live yet". On a
// successful load the stale-availability copy is absent; on a real
// failure an honest error state still renders.

function emptyOverview(): DashboardOverview {
  return {
    streak_days: 0,
    due_reviews_count: 0,
    concepts: { count_total: 0, counts_by_domain: {}, rows: [] },
    due_today: { count: 0, items: [] },
    recent_observations: [],
  };
}

describe('LearningDashboardPageComponent — availability copy', () => {
  let fixture: ComponentFixture<LearningDashboardPageComponent>;

  afterEach(() => TestBed.resetTestingModule());

  async function render(
    dashboard: () => ReturnType<LearningService['dashboard']>,
  ): Promise<HTMLElement> {
    TestBed.configureTestingModule({
      imports: [LearningDashboardPageComponent],
      providers: [
        provideRouter([]),
        { provide: LearningService, useValue: { dashboard } },
        {
          provide: NotificationService,
          useValue: {
            success: () => undefined,
            error: () => undefined,
            info: () => undefined,
          },
        },
        {
          provide: AdminTopbarService,
          useValue: { set: () => undefined, reset: () => undefined },
        },
      ],
    });
    fixture = TestBed.createComponent(LearningDashboardPageComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('renders the dashboard chrome without stale "not live" copy when the service succeeds', async () => {
    const el = await render(() => of(emptyOverview()));

    // The data view renders (empty states), not the unavailable banner.
    expect(el.querySelector('[data-testid="learning-chrome"]')).toBeTruthy();
    expect(
      el.querySelector('[data-testid="learning-endpoints-pending"]'),
    ).toBeNull();
    expect(el.textContent).not.toContain('not live yet');
    expect(el.textContent).not.toContain('Endpoints pending');
  });

  it('renders an honest "couldn\'t load" message (not "not live yet") on a 404', async () => {
    const el = await render(() =>
      throwError(() => new HttpErrorResponse({ status: 404 })),
    );

    const banner = el.querySelector(
      '[data-testid="learning-endpoints-pending"]',
    );
    expect(banner).toBeTruthy();
    expect(banner?.textContent).toContain("Couldn't load");
    expect(banner?.textContent).not.toContain('not live yet');
  });

  it('renders the generic error state on a real backend failure', async () => {
    const el = await render(() =>
      throwError(() => new HttpErrorResponse({ status: 500 })),
    );

    const error = el.querySelector('[data-testid="learning-error"]');
    expect(error).toBeTruthy();
    expect(error?.textContent).toContain("Couldn't load dashboard");
  });
});
