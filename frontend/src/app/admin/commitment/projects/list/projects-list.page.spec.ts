import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';
import { vi } from 'vitest';

import { ProjectsListPageComponent } from './projects-list.page';
import type { ProjectSummary } from '../../../../core/models/admin.model';

const PROJECTS_URL = '/api/admin/commitment/projects';

/** A ProjectSummary row with sensible defaults. */
function row(overrides: Partial<ProjectSummary>): ProjectSummary {
  return {
    id: 'p1',
    title: 'Knowledge engine',
    slug: 'knowledge-engine',
    status: 'in_progress',
    area: 'Build',
    goal_breadcrumb: null,
    todo_progress: { total: 4, done: 1 },
    staleness_days: 2,
    last_activity_at: '2026-06-18T00:00:00Z',
    ...overrides,
  };
}

const ROWS: ProjectSummary[] = [
  row({ id: 'p1', title: 'Knowledge engine', status: 'in_progress' }),
  row({ id: 'p2', title: 'Planned migration', status: 'planned' }),
  row({
    id: 'p3',
    title: 'Old archived project',
    status: 'archived',
    area: '',
    todo_progress: { total: 2, done: 2 },
    last_activity_at: null,
  }),
];

describe('ProjectsListPageComponent', () => {
  let fixture: ComponentFixture<ProjectsListPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ProjectsListPageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
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

  /** Flush the single list GET; rxResource resolves on a macrotask. */
  async function render(body: ProjectSummary[]): Promise<void> {
    fixture = TestBed.createComponent(ProjectsListPageComponent);
    fixture.detectChanges();
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.url.endsWith(PROJECTS_URL))
      .flush({ data: body });
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('should request the unfiltered projects endpoint exactly once (no ?status=)', async () => {
    fixture = TestBed.createComponent(ProjectsListPageComponent);
    fixture.detectChanges();
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();

    const req = httpMock.expectOne((r) => r.url.endsWith(PROJECTS_URL));
    expect(req.request.method).toBe('GET');
    expect(req.request.params.has('status')).toBe(false);
    req.flush({ data: ROWS });
    await fixture.whenStable();
    fixture.detectChanges();
  });

  it('should render area and task progress from the projects envelope', async () => {
    await render(ROWS);

    const firstRow = testid('projects-list-row-0');
    expect(firstRow?.textContent).toContain('Knowledge engine');
    expect(firstRow?.textContent).toContain('Build');
    expect(firstRow?.textContent).toContain('1 / 4');
  });

  it('should default to the active filter (in_progress + planned)', async () => {
    await render(ROWS);

    // Active hides the archived row; p1 + p2 remain.
    expect(testid('projects-count')?.textContent).toContain('2 projects');
    expect(testid('projects-list-row-0')?.textContent).toContain(
      'Knowledge engine',
    );
    expect(testid('projects-list-row-1')?.textContent).toContain(
      'Planned migration',
    );
    expect(el().textContent).not.toContain('Old archived project');
  });

  it('should reveal every status when the All chip is selected (client-side, no refetch)', async () => {
    await render(ROWS);

    (testid('projects-filter-status-all') as HTMLButtonElement).click();
    fixture.detectChanges();

    expect(testid('projects-count')?.textContent).toContain('3 projects');
    expect(el().textContent).toContain('Old archived project');
    // No second HTTP request — filtering is pure client-side.
    httpMock.expectNone((r) => r.url.endsWith(PROJECTS_URL));
  });

  it('should filter to a single status when its chip is selected', async () => {
    await render(ROWS);

    (testid('projects-filter-status-archived') as HTMLButtonElement).click();
    fixture.detectChanges();

    expect(testid('projects-count')?.textContent).toContain('1 project');
    expect(el().textContent).toContain('Old archived project');
    expect(el().textContent).not.toContain('Knowledge engine');
  });

  it('should show a dash for a project with no area', async () => {
    await render([row({ id: 'p3', status: 'archived', area: '' })]);
    (testid('projects-filter-status-all') as HTMLButtonElement).click();
    fixture.detectChanges();

    expect(testid('projects-list-row-0')?.textContent).toContain('—');
  });

  it('should navigate to the project detail when a row is opened', async () => {
    await render(ROWS);
    const navigateSpy = vi
      .spyOn(TestBed.inject(Router), 'navigate')
      .mockResolvedValue(true);

    (testid('projects-list-row-0') as HTMLElement).click();

    expect(navigateSpy).toHaveBeenCalledWith([
      '/admin/commitment/projects',
      'p1',
    ]);
  });

  // flush-500: a failed load must NOT throw (hasValue() guard) and must
  // render the error banner. Without the guard, value() throws while the
  // resource is in error state and takes the page down.
  it('should surface the error banner when the list read fails (no throw)', async () => {
    fixture = TestBed.createComponent(ProjectsListPageComponent);
    fixture.detectChanges();
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.url.endsWith(PROJECTS_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Server Error' },
      );
    await fixture.whenStable();
    fixture.detectChanges();

    expect(testid('projects-list-error')).not.toBeNull();
  });
});
