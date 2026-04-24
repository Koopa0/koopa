import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { GoalInspectorComponent } from './goal-inspector.component';
import type { GoalDetail } from '../../../../core/models/admin.model';

describe('GoalInspectorComponent', () => {
  let fixture: ComponentFixture<GoalInspectorComponent>;
  let httpMock: HttpTestingController;

  const mockGoal: GoalDetail = {
    id: 'g1',
    title: 'mcp rewrite',
    description: 'Rewrite MCP server v2',
    status: 'in_progress',
    area_id: 'a1',
    area_name: 'backend',
    deadline: null,
    quarter: '2026-Q2',
    created_at: '2026-04-01T00:00:00Z',
    health: 'on-track',
    milestones: [
      {
        id: 'm1',
        title: 'design spec',
        completed: true,
        completed_at: '2026-04-08T00:00:00Z',
        position: 1,
      },
      {
        id: 'm2',
        title: 'phase 1 impl',
        completed: false,
        completed_at: null,
        position: 2,
      },
    ],
    projects: [
      {
        id: 'p1',
        title: 'mcp v2 rewrite',
        status: 'in_progress',
        task_progress: { done: 6, total: 14 },
      },
    ],
    recent_activity: [
      {
        type: 'task_completed',
        title: 'wrote errgroup tests',
        timestamp: '2026-04-13T09:34:00Z',
      },
    ],
  };

  function setupFixture(): void {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideNoopAnimations(),
      ],
    });
    fixture = TestBed.createComponent(GoalInspectorComponent);
    httpMock = TestBed.inject(HttpTestingController);
  }

  /**
   * rxResource may fire the loader more than once during a single test
   * lifecycle (initial signal read + post-flush stabilization). Use
   * `match()` to flush every pending request to the same URL with the
   * mock response and then verify nothing else is left dangling.
   */
  function flushAllGoalRequests(id: string, response: GoalDetail | null): void {
    const reqs = httpMock.match(`/bff/api/admin/commitment/goals/${id}`);
    expect(reqs.length).toBeGreaterThan(0);
    for (const r of reqs) {
      if (response === null) {
        r.flush(null, { status: 500, statusText: 'Internal Server Error' });
      } else {
        r.flush(response);
      }
    }
  }

  it('should fetch goal detail and render title in overview tab', async () => {
    setupFixture();
    fixture.componentRef.setInput('id', 'g1');
    fixture.detectChanges();

    flushAllGoalRequests('g1', mockGoal);

    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    const titleEl = fixture.nativeElement.querySelector(
      '[data-testid="goal-title"]',
    ) as HTMLElement | null;
    expect(titleEl?.textContent).toContain('mcp rewrite');

    const overview = fixture.nativeElement.querySelector(
      '[data-testid="goal-overview-section"]',
    );
    expect(overview).toBeTruthy();
    const activity = fixture.nativeElement.querySelector(
      '[data-testid="goal-activity-section"]',
    );
    expect(activity).toBeNull();

    httpMock.verify();
  });

  it('should render activity section when activity tab is clicked', async () => {
    setupFixture();
    fixture.componentRef.setInput('id', 'g1');
    fixture.detectChanges();

    flushAllGoalRequests('g1', mockGoal);

    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    const activityTab = fixture.nativeElement.querySelector(
      '[data-testid="goal-tab-activity"]',
    ) as HTMLButtonElement;
    activityTab.click();
    fixture.detectChanges();

    const activity = fixture.nativeElement.querySelector(
      '[data-testid="goal-activity-section"]',
    ) as HTMLElement;
    expect(activity).toBeTruthy();
    expect(activity.textContent).toContain('wrote errgroup tests');

    const overview = fixture.nativeElement.querySelector(
      '[data-testid="goal-overview-section"]',
    );
    expect(overview).toBeNull();

    httpMock.verify();
  });

  it('should render error state when fetch fails', async () => {
    setupFixture();
    fixture.componentRef.setInput('id', 'g1');
    fixture.detectChanges();

    flushAllGoalRequests('g1', null);

    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    const errorEl = fixture.nativeElement.querySelector('[role="alert"]');
    expect(errorEl).toBeTruthy();
    expect(errorEl.textContent).toContain('Failed to load goal');

    httpMock.verify();
  });
});
