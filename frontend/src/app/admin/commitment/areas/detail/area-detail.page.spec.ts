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

import { AreaDetailPageComponent } from './area-detail.page';
import type {
  AreaDetail,
  GoalSummary,
} from '../../../../core/models/admin.model';

const DETAIL_URL = '/api/admin/commitment/areas/area-1';

function goal(overrides: Partial<GoalSummary> = {}): GoalSummary {
  return {
    id: 'g1',
    title: 'Ship koopa v1',
    description: '',
    status: 'in_progress',
    area_id: 'area-1',
    area_name: 'Build',
    milestone_total: 3,
    milestone_done: 1,
    created_at: '2026-06-01T00:00:00Z',
    updated_at: '2026-06-01T00:00:00Z',
    ...overrides,
  };
}

function detail(overrides: Partial<AreaDetail> = {}): AreaDetail {
  return {
    area: {
      id: 'area-1',
      slug: 'build',
      name: 'Build',
      description: 'Ship the platform.',
      status: 'active',
      sort_order: 1,
      created_at: '2026-05-01T00:00:00Z',
      updated_at: '2026-06-01T00:00:00Z',
    },
    goals: [goal(), goal({ id: 'g2', title: 'Ship koopa v2' })],
    projects: [{ id: 'p1', title: 'koopa-core', status: 'in_progress' }],
    ...overrides,
  };
}

describe('AreaDetailPageComponent', () => {
  let fixture: ComponentFixture<AreaDetailPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [AreaDetailPageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        {
          provide: ActivatedRoute,
          useValue: { paramMap: of(convertToParamMap({ id: 'area-1' })) },
        },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
    TestBed.resetTestingModule();
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function testid(id: string): HTMLElement | null {
    return el().querySelector(`[data-testid="${id}"]`);
  }

  /** Flush the single detail GET; rxResource resolves on a macrotask. */
  async function render(body: AreaDetail): Promise<void> {
    fixture = TestBed.createComponent(AreaDetailPageComponent);
    fixture.detectChanges();
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.url.endsWith(DETAIL_URL))
      .flush({ data: body });
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('should render the area header, goals, and projects from the detail read', async () => {
    await render(detail());

    expect(testid('area-hero')?.textContent).toContain('Build');
    expect(testid('area-status')?.textContent).toContain('active');
    expect(testid('area-description')?.textContent).toContain(
      'Ship the platform.',
    );
    expect(testid('area-goal-g1')?.textContent).toContain('Ship koopa v1');
    expect(testid('area-goal-g1')?.textContent).toContain('1/3');
    expect(testid('area-goal-g2')?.textContent).toContain('Ship koopa v2');
    expect(testid('area-project-p1')?.textContent).toContain('koopa-core');
  });

  it('should link each goal and project row to its own detail', async () => {
    await render(detail());

    expect(testid('area-goal-g1')?.getAttribute('href')).toContain(
      '/admin/commitment/goals/g1',
    );
    expect(testid('area-project-p1')?.getAttribute('href')).toContain(
      '/admin/commitment/projects/p1',
    );
  });

  it('should show empty states when the area has no goals or projects', async () => {
    await render(detail({ goals: [], projects: [] }));

    expect(testid('area-goals-empty')?.textContent).toContain(
      'No goals in this area yet.',
    );
    expect(testid('area-projects-empty')?.textContent).toContain(
      'No projects in this area yet.',
    );
  });

  // flush-500: a failed load must NOT throw (hasValue() guard) and must render
  // the error banner. Without the guard, value() throws while the resource is
  // in error state and takes the page down.
  it('should surface the error banner when the detail read fails (no throw)', async () => {
    fixture = TestBed.createComponent(AreaDetailPageComponent);
    fixture.detectChanges();
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.url.endsWith(DETAIL_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Server Error' },
      );
    await fixture.whenStable();
    fixture.detectChanges();

    expect(testid('area-detail-error')).not.toBeNull();
    expect(testid('area-hero')).toBeNull();
  });
});
