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

import { ProjectProfilePageComponent } from './project-profile.page';
import type { ProjectDetail } from '../../../../core/models/admin.model';

const DETAIL_URL = '/api/admin/commitment/projects/p1';

function detail(overrides?: Partial<ProjectDetail>): ProjectDetail {
  return {
    id: 'p1',
    title: 'koopa-core',
    slug: 'koopa-core',
    description: 'The core engine.',
    status: 'active',
    area: 'Build',
    goal_breadcrumb: null,
    todos_by_state: {
      in_progress: [
        {
          id: 't1',
          title: 'Wire the store',
          priority: 'high',
          energy: 'deep',
          due: null,
          is_in_today_plan: false,
        },
      ],
      todo: [],
      done: [],
      someday: [],
    },
    recent_activity: [],
    related_content: [],
    ...overrides,
  };
}

describe('ProjectProfilePageComponent', () => {
  let fixture: ComponentFixture<ProjectProfilePageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ProjectProfilePageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        {
          provide: ActivatedRoute,
          useValue: { paramMap: of(convertToParamMap({ id: 'p1' })) },
        },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    try {
      flushDetail(detail());
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

  function flushDetail(body: ProjectDetail): number {
    const reqs = httpMock.match(
      (r) => r.method === 'GET' && r.url.endsWith(DETAIL_URL),
    );
    for (const r of reqs) r.flush({ data: body });
    return reqs.length;
  }

  async function settle(): Promise<void> {
    await fixture.whenStable();
    fixture.detectChanges();
  }

  async function render(body: ProjectDetail): Promise<void> {
    fixture = TestBed.createComponent(ProjectProfilePageComponent);
    fixture.detectChanges();
    expect(flushDetail(body)).toBeGreaterThan(0);
    await settle();
    flushDetail(body);
    fixture.detectChanges();
  }

  it('should render the hero and grouped todos from the detail wire', async () => {
    await render(detail());

    expect(testid('project-hero')?.textContent).toContain('koopa-core');
    expect(testid('project-todos')?.textContent).toContain('Wire the store');
  });

  it('should not crash when todos_by_state is null (no todo store wired)', async () => {
    // The Go handler leaves todos_by_state as an uninitialised `any` (null on
    // the wire) when no todo store is wired — the page must tolerate it.
    await render(detail({ todos_by_state: null }));

    expect(testid('project-profile')).not.toBeNull();
    expect(testid('project-hero')?.textContent).toContain('koopa-core');
  });

  it('should render the error notice without throwing when the detail load fails', async () => {
    // project() reads rxResource.value(), which throws in the error state. The
    // constructor effect reads it eagerly, so without the hasValue() guard this
    // throws during change detection instead of showing the error notice.
    fixture = TestBed.createComponent(ProjectProfilePageComponent);
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
    await settle();
    failDetail(); // drain any loader the resource re-fired on settle
    await settle();

    expect(testid('project-error')).not.toBeNull();
    expect(testid('project-hero')).toBeNull();
  });
});
