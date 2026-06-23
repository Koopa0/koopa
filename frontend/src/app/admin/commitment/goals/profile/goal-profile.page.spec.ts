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
} from '@angular/router';
import { of } from 'rxjs';

import { GoalProfilePageComponent } from './goal-profile.page';
import { NotificationService } from '../../../../core/services/notification.service';
import type { GoalDetail } from '../../../../core/models/admin.model';

const DETAIL_URL = '/api/admin/commitment/goals/g1';
const STATUS_URL = '/api/admin/commitment/goals/g1/status';
const MILESTONES_URL = '/api/admin/commitment/goals/g1/milestones';
const MILESTONE_M1_URL = '/api/admin/commitment/goals/g1/milestones/m1';
const TOGGLE_URL = '/api/admin/commitment/goals/g1/milestones/m1/toggle';
const AREAS_URL = '/api/admin/commitment/areas';

const AREA_ROWS = [
  { id: 'area-1', slug: 'build', name: 'Build', sort_order: 1 },
  { id: 'area-2', slug: 'career', name: 'Career', sort_order: 2 },
];

function detail(overrides?: Partial<GoalDetail>): GoalDetail {
  return {
    id: 'g1',
    title: 'Ship koopa v1',
    description: 'Stable, self-hostable release.',
    status: 'not_started',
    area_id: 'area-1',
    area_name: 'Build',
    quarter: '2026-Q3',
    deadline: '2026-09-30',
    milestones: [
      {
        id: 'm1',
        goal_id: 'g1',
        title: 'Cut the first RC',
        description: '',
        position: 0,
        created_at: '2026-06-01T00:00:00Z',
        updated_at: '2026-06-01T00:00:00Z',
      },
      {
        id: 'm2',
        goal_id: 'g1',
        title: 'Write the install guide',
        description: '',
        completed_at: '2026-06-05T00:00:00Z',
        position: 1,
        created_at: '2026-06-01T00:00:00Z',
        updated_at: '2026-06-05T00:00:00Z',
      },
    ],
    projects: [{ id: 'p1', title: 'koopa-core', status: 'active' }],
    recent_activity: [
      {
        type: 'milestone',
        title: 'Write the install guide',
        ref_id: 'm2',
        timestamp: '2026-06-05T00:00:00Z',
      },
    ],
    created_at: '2026-05-01T00:00:00Z',
    updated_at: '2026-06-05T00:00:00Z',
    ...overrides,
  };
}

describe('GoalProfilePageComponent', () => {
  let fixture: ComponentFixture<GoalProfilePageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [GoalProfilePageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        {
          provide: ActivatedRoute,
          useValue: { paramMap: of(convertToParamMap({ id: 'g1' })) },
        },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    try {
      // rxResource may re-fire the detail loader during stabilization;
      // drain any stragglers (detail + areas) before asserting clean.
      flushDetail(detail());
      flushAreas();
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

  /** Flushes every pending detail GET; returns how many were open. */
  function flushDetail(body: GoalDetail): number {
    const reqs = httpMock.match(
      (r) => r.method === 'GET' && r.url.endsWith(DETAIL_URL),
    );
    for (const r of reqs) {
      r.flush({ data: body });
    }
    return reqs.length;
  }

  /** Drain the areas read (fired once on init for the edit form selector). */
  function flushAreas(): void {
    httpMock
      .match((r) => r.method === 'GET' && r.url.endsWith(AREAS_URL))
      .forEach((r) => r.flush({ data: AREA_ROWS }));
  }

  async function settle(): Promise<void> {
    await fixture.whenStable();
    fixture.detectChanges();
  }

  // Flush the in-flight detail + areas requests before awaiting stability —
  // pending HTTP counts as a pending task in zoneless mode.
  async function render(body: GoalDetail): Promise<void> {
    fixture = TestBed.createComponent(GoalProfilePageComponent);
    fixture.detectChanges();
    expect(flushDetail(body)).toBeGreaterThan(0);
    flushAreas();
    await settle();
    flushDetail(body);
    flushAreas();
    fixture.detectChanges();
  }

  function toastMessages(): string[] {
    return TestBed.inject(NotificationService)
      .notifications()
      .map((n) => n.message);
  }

  it('should render title, meta strip, milestones, projects, and activity from the detail response', async () => {
    await render(detail());

    expect(testid('goal-hero')?.textContent).toContain('Ship koopa v1');
    expect(testid('goal-meta')?.textContent).toContain('2026-Q3');
    expect(testid('goal-milestone-count')?.textContent).toContain('1/2');
    expect(testid('goal-milestones')?.textContent).toContain('Cut the first RC');
    expect(testid('goal-project-p1')?.textContent).toContain('koopa-core');
    expect(testid('goal-activity')?.textContent).toContain(
      'Write the install guide',
    );
  });

  it('should update status and re-fetch the detail because the response is partial', async () => {
    await render(detail());

    (testid('goal-status-toggle') as HTMLButtonElement).click();
    await settle();
    (testid('goal-status-option-in_progress') as HTMLButtonElement).click();
    fixture.detectChanges();

    const put = httpMock.expectOne((r) => r.url.endsWith(STATUS_URL));
    expect(put.request.method).toBe('PUT');
    expect(put.request.body).toEqual({ status: 'in_progress' });
    put.flush({
      data: {
        title: 'Ship koopa v1',
        status: 'in_progress',
        area_id: null,
        updated_at: '2026-06-10T00:00:00Z',
      },
    });
    fixture.detectChanges();

    expect(flushDetail(detail({ status: 'in_progress' }))).toBeGreaterThan(0);
    await settle();
    flushDetail(detail({ status: 'in_progress' }));
    fixture.detectChanges();

    expect(testid('goal-status-toggle')?.textContent).toContain('in progress');
    expect(toastMessages()).toContain('Status → in progress');
  });

  it('should add a milestone through the inline form and reload the detail', async () => {
    await render(detail());

    const input = testid('goal-milestone-input') as HTMLInputElement;
    input.value = 'Publish the launch post';
    input.dispatchEvent(new Event('input'));
    await settle();

    (testid('goal-milestone-add-btn') as HTMLButtonElement).click();
    fixture.detectChanges();

    const post = httpMock.expectOne(
      (r) => r.method === 'POST' && r.url.endsWith(MILESTONES_URL),
    );
    expect(post.request.body).toEqual({ title: 'Publish the launch post' });
    post.flush({
      data: { id: 'm3', goal_id: 'g1', title: 'Publish the launch post' },
    });
    fixture.detectChanges();

    expect(flushDetail(detail())).toBeGreaterThan(0);
    await settle();
    flushDetail(detail());
    fixture.detectChanges();

    expect(toastMessages()).toContain('Milestone added');
    expect((testid('goal-milestone-input') as HTMLInputElement).value).toBe('');
  });

  it('should toggle a milestone and reload the detail', async () => {
    await render(detail());

    (testid('goal-milestone-m1') as HTMLButtonElement).click();
    fixture.detectChanges();

    const post = httpMock.expectOne((r) => r.url.endsWith(TOGGLE_URL));
    expect(post.request.method).toBe('POST');
    post.flush({
      data: { id: 'm1', goal_id: 'g1', completed_at: '2026-06-10T00:00:00Z' },
    });
    fixture.detectChanges();

    expect(flushDetail(detail())).toBeGreaterThan(0);
    await settle();
    flushDetail(detail());
    fixture.detectChanges();
  });

  // --- Edit goal ---

  it('should PUT only the changed shaping fields and reload after edit', async () => {
    await render(detail());

    (testid('goal-edit-toggle') as HTMLButtonElement).click();
    fixture.detectChanges();

    const title = testid('goal-edit-title') as HTMLInputElement;
    expect(title.value).toBe('Ship koopa v1');
    title.value = 'Ship koopa v1.0';
    title.dispatchEvent(new Event('input'));
    await settle();

    (testid('goal-edit-save') as HTMLButtonElement).click();
    fixture.detectChanges();

    const put = httpMock.expectOne(
      (r) => r.method === 'PUT' && r.url.endsWith(DETAIL_URL),
    );
    // Only the title changed; description/quarter/area/deadline stay omitted.
    expect(put.request.body).toEqual({ title: 'Ship koopa v1.0' });
    put.flush({
      data: {
        id: 'g1',
        title: 'Ship koopa v1.0',
        description: 'Stable, self-hostable release.',
        status: 'not_started',
        created_at: '2026-05-01T00:00:00Z',
        updated_at: '2026-06-11T00:00:00Z',
      },
    });
    fixture.detectChanges();

    expect(flushDetail(detail({ title: 'Ship koopa v1.0' }))).toBeGreaterThan(0);
    await settle();
    flushDetail(detail({ title: 'Ship koopa v1.0' }));
    fixture.detectChanges();

    expect(toastMessages()).toContain('Goal updated');
    expect(testid('goal-hero')?.textContent).toContain('Ship koopa v1.0');
  });

  it('should leave the goal unchanged and not call the API when edit is cancelled', async () => {
    await render(detail());

    (testid('goal-edit-toggle') as HTMLButtonElement).click();
    fixture.detectChanges();
    (testid('goal-edit-cancel') as HTMLButtonElement).click();
    fixture.detectChanges();

    httpMock.expectNone(
      (r) => r.method === 'PUT' && r.url.endsWith(DETAIL_URL),
    );
    expect(testid('goal-hero')).not.toBeNull();
  });

  // --- Milestone delete (two-step confirm) ---

  it('should require a confirm before DELETE and then reload the detail', async () => {
    await render(detail());

    (testid('goal-milestone-delete-m1') as HTMLButtonElement).click();
    fixture.detectChanges();
    // First click only reveals the confirm — no request yet.
    httpMock.expectNone(
      (r) => r.method === 'DELETE' && r.url.endsWith(MILESTONE_M1_URL),
    );

    (testid('goal-milestone-delete-confirm-m1') as HTMLButtonElement).click();
    fixture.detectChanges();

    const del = httpMock.expectOne(
      (r) => r.method === 'DELETE' && r.url.endsWith(MILESTONE_M1_URL),
    );
    del.flush(null, { status: 204, statusText: 'No Content' });
    fixture.detectChanges();

    expect(flushDetail(detail())).toBeGreaterThan(0);
    await settle();
    flushDetail(detail());
    fixture.detectChanges();

    expect(toastMessages()).toContain('Milestone deleted');
  });

  it('should not DELETE when the delete confirm is dismissed', async () => {
    await render(detail());

    (testid('goal-milestone-delete-m1') as HTMLButtonElement).click();
    fixture.detectChanges();
    (testid('goal-milestone-delete-cancel-m1') as HTMLButtonElement).click();
    fixture.detectChanges();

    httpMock.expectNone(
      (r) => r.method === 'DELETE' && r.url.endsWith(MILESTONE_M1_URL),
    );
  });

  // --- Inline milestone title edit ---

  it('should PUT the new milestone title and reload after inline edit', async () => {
    await render(detail());

    (testid('goal-milestone-edit-toggle-m1') as HTMLButtonElement).click();
    fixture.detectChanges();

    const input = testid('goal-milestone-edit-input-m1') as HTMLInputElement;
    expect(input.value).toBe('Cut the first RC');
    input.value = 'Cut the first release candidate';
    input.dispatchEvent(new Event('input'));
    await settle();

    (testid('goal-milestone-edit-save-m1') as HTMLButtonElement).click();
    fixture.detectChanges();

    const put = httpMock.expectOne(
      (r) => r.method === 'PUT' && r.url.endsWith(MILESTONE_M1_URL),
    );
    expect(put.request.body).toEqual({
      title: 'Cut the first release candidate',
    });
    put.flush({
      data: {
        id: 'm1',
        goal_id: 'g1',
        title: 'Cut the first release candidate',
      },
    });
    fixture.detectChanges();

    expect(flushDetail(detail())).toBeGreaterThan(0);
    await settle();
    flushDetail(detail());
    fixture.detectChanges();

    expect(toastMessages()).toContain('Milestone updated');
  });

  it('should render the error notice without throwing when the detail load fails', async () => {
    // goal() reads rxResource.value(), which throws in the error state. The
    // constructor effect reads it eagerly, so without the hasValue() guard this
    // throws during change detection instead of showing the error notice.
    fixture = TestBed.createComponent(GoalProfilePageComponent);
    fixture.detectChanges();

    const failDetail = (): number => {
      const reqs = httpMock.match(
        (r) => r.method === 'GET' && r.url.endsWith(DETAIL_URL),
      );
      for (const r of reqs) {
        r.flush({ error: 'boom' }, { status: 500, statusText: 'Server Error' });
      }
      return reqs.length;
    };

    expect(failDetail()).toBeGreaterThan(0);
    flushAreas();
    await settle();
    failDetail(); // drain any loader the resource re-fired on settle
    flushAreas();
    await settle();

    expect(testid('goal-error')).not.toBeNull();
    expect(testid('goal-hero')).toBeNull();
  });
});
