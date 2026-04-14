import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';
import { signal } from '@angular/core';
import { AuthService } from '../../core/services/auth.service';
import { CommandPaletteService } from './command-palette.service';
import type {
  GoalsOverview,
  ProjectSummary,
} from '../../core/models/admin.model';

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
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
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

  it('should load goals and projects when opening while authenticated', () => {
    const { httpMock } = setup(true);

    const goalsResponse: GoalsOverview = {
      by_area: [
        {
          area_id: 'a1',
          area_name: 'backend',
          area_slug: 'backend',
          goals: [
            {
              id: 'g1',
              title: 'mcp rewrite',
              status: 'in-progress',
              deadline: null,
              days_remaining: null,
              milestones_total: 7,
              milestones_done: 4,
              next_milestone_title: 'phase 2',
              projects_count: 1,
              quarter: '2026-Q2',
            },
          ],
        },
      ],
    };

    const projectsResponse: { projects: ProjectSummary[] } = {
      projects: [
        {
          id: 'p1',
          title: 'studio launch',
          slug: 'studio-launch',
          status: 'in-progress',
          area: 'studio',
          goal_breadcrumb: null,
          task_progress: { done: 2, total: 8 },
          staleness_days: 1,
          last_activity_at: null,
        },
      ],
    };

    service.open();

    httpMock.expectOne('/bff/api/admin/plan/goals').flush(goalsResponse);
    httpMock.expectOne('/bff/api/admin/plan/projects').flush(projectsResponse);

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
    expect(projectActions[0].keywords).toEqual(['studio', 'in-progress']);

    httpMock.verify();
  });

  it('should not fetch admin entities when opening unauthenticated', () => {
    const { httpMock } = setup(false);

    service.open();

    httpMock.expectNone('/bff/api/admin/plan/goals');
    httpMock.expectNone('/bff/api/admin/plan/projects');
    httpMock.verify();
  });

  it('should fetch admin entities only once across multiple opens', () => {
    const { httpMock } = setup(true);

    service.open();
    httpMock.expectOne('/bff/api/admin/plan/goals').flush({ by_area: [] });
    httpMock.expectOne('/bff/api/admin/plan/projects').flush({ projects: [] });

    service.close();
    service.open();

    httpMock.expectNone('/bff/api/admin/plan/goals');
    httpMock.expectNone('/bff/api/admin/plan/projects');
    httpMock.verify();
  });
});
