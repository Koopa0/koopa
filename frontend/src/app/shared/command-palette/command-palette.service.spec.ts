import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';
import { signal } from '@angular/core';
import { AuthService } from '../../core/services/auth.service';
import { CommandPaletteService } from './command-palette.service';
import type { GoalSummary, ProjectSummary } from '../../core/models/admin.model';

describe('CommandPaletteService', () => {
  let service: CommandPaletteService;

  function setup(authenticated = false): {
    httpMock: HttpTestingController;
    router: Router;
  } {
    const authStub = {
      isAuthenticated: signal(authenticated),
    };

    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        // Wildcard route so tests can navigate into /admin (the palette's
        // admin quick-nav is gated to the admin area).
        provideRouter([{ path: '**', children: [] }]),
        { provide: AuthService, useValue: authStub },
      ],
    });
    service = TestBed.inject(CommandPaletteService);

    return {
      httpMock: TestBed.inject(HttpTestingController),
      router: TestBed.inject(Router),
    };
  }

  it('should be created', () => {
    setup();
    expect(service).toBeTruthy();
  });

  it('should start closed', () => {
    setup();
    expect(service.isOpen()).toBe(false);
  });

  it('should open and close', () => {
    setup();
    service.open();
    expect(service.isOpen()).toBe(true);

    service.close();
    expect(service.isOpen()).toBe(false);
  });

  it('should toggle', () => {
    setup();
    service.toggle();
    expect(service.isOpen()).toBe(true);

    service.toggle();
    expect(service.isOpen()).toBe(false);
  });

  it('should have page actions', () => {
    setup();
    const actions = service.actions();
    const pageActions = actions.filter((a) => a.group === 'Pages');
    expect(pageActions.length).toBeGreaterThan(0);
    expect(pageActions.some((a) => a.id === 'home')).toBe(true);
    expect(pageActions.some((a) => a.id === 'articles')).toBe(true);
  });

  it('should not have admin actions when unauthenticated', () => {
    setup(false);
    const actions = service.actions();
    const adminActions = actions.filter((a) => a.group === 'Admin');
    expect(adminActions.length).toBe(0);
  });

  it('should not surface admin nav on a public route even when authenticated', async () => {
    const { httpMock, router } = setup(true);
    await router.navigateByUrl('/');
    service.open();
    // The owner is authed, so the entity load still fires — drain it.
    httpMock.expectOne('https://koopa0.dev/api/admin/commitment/goals').flush([]);
    httpMock
      .expectOne('https://koopa0.dev/api/admin/commitment/projects')
      .flush({ data: [] });
    httpMock
      .expectOne((r) => r.url.includes('https://koopa0.dev/api/admin/knowledge/content'))
      .flush({ data: [] });

    const actions = service.actions();
    expect(actions.filter((a) => a.group === 'Admin')).toHaveLength(0);
    expect(actions.filter((a) => a.group === 'Goals')).toHaveLength(0);
    // Public page nav stays available.
    expect(actions.some((a) => a.id === 'home')).toBe(true);
    httpMock.verify();
  });

  it('should load goals and projects when opening while authenticated', async () => {
    const { httpMock, router } = setup(true);
    // Admin entity actions only surface in the admin area.
    await router.navigateByUrl('/admin/daily/today');

    const goalsResponse: GoalSummary[] = [
      {
        id: 'g1',
        title: 'mcp rewrite',
        description: '',
        status: 'in_progress',
        quarter: '2026-Q2',
        created_at: '2026-06-01T00:00:00Z',
        updated_at: '2026-06-01T00:00:00Z',
        area_name: 'backend',
        milestone_total: 7,
        milestone_done: 4,
      },
    ];

    const projectsResponse: { data: ProjectSummary[] } = {
      data: [
        {
          id: 'p1',
          title: 'studio launch',
          slug: 'studio-launch',
          status: 'in_progress',
          area: 'studio',
          goal_breadcrumb: null,
          todo_progress: { done: 2, total: 8 },
          staleness_days: 1,
          last_activity_at: null,
        },
      ],
    };

    service.open();

    httpMock.expectOne('https://koopa0.dev/api/admin/commitment/goals').flush(goalsResponse);
    httpMock.expectOne('https://koopa0.dev/api/admin/commitment/projects').flush(projectsResponse);
    httpMock
      .expectOne((r) => r.url.includes('https://koopa0.dev/api/admin/knowledge/content'))
      .flush({ data: [] });

    const actions = service.actions();
    const goalActions = actions.filter((a) => a.group === 'Goals');
    const projectActions = actions.filter((a) => a.group === 'Projects');

    expect(goalActions).toHaveLength(1);
    expect(goalActions[0].id).toBe('goal:g1');
    expect(goalActions[0].label).toBe('mcp rewrite');
    expect(goalActions[0].keywords).toEqual(['backend', '2026-Q2']);

    expect(projectActions).toHaveLength(1);
    expect(projectActions[0].id).toBe('project:p1');
    expect(projectActions[0].label).toBe('studio launch');
    expect(projectActions[0].keywords).toEqual(['studio', 'in_progress']);

    httpMock.verify();
  });

  it('should not fetch admin entities when opening unauthenticated', () => {
    const { httpMock } = setup(false);

    service.open();

    httpMock.expectNone('https://koopa0.dev/api/admin/commitment/goals');
    httpMock.expectNone('https://koopa0.dev/api/admin/commitment/projects');
    httpMock.verify();
  });

  it('should fetch admin entities only once across multiple opens', () => {
    const { httpMock } = setup(true);

    service.open();
    httpMock.expectOne('https://koopa0.dev/api/admin/commitment/goals').flush([]);
    httpMock.expectOne('https://koopa0.dev/api/admin/commitment/projects').flush({ data: [] });
    httpMock
      .expectOne((r) => r.url.includes('https://koopa0.dev/api/admin/knowledge/content'))
      .flush({ data: [] });

    service.close();
    service.open();

    httpMock.expectNone('https://koopa0.dev/api/admin/commitment/goals');
    httpMock.expectNone('https://koopa0.dev/api/admin/commitment/projects');
    httpMock.expectNone((r) => r.url.includes('https://koopa0.dev/api/admin/knowledge/content'));
    httpMock.verify();
  });
});
