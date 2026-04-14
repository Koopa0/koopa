import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { AtlasPageComponent } from './atlas-page.component';
import type {
  GoalsOverview,
  ProjectSummary,
} from '../../core/models/admin.model';

const MOCK_GOALS: GoalsOverview = {
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
          next_milestone_title: null,
          projects_count: 1,
          quarter: '2026-Q2',
        },
      ],
    },
    {
      area_id: 'a2',
      area_name: 'studio',
      area_slug: 'studio',
      goals: [
        {
          id: 'g2',
          title: 'koopa studio launch',
          status: 'in-progress',
          deadline: null,
          days_remaining: null,
          milestones_total: 3,
          milestones_done: 1,
          next_milestone_title: null,
          projects_count: 0,
          quarter: '2026-Q2',
        },
      ],
    },
  ],
};

const MOCK_PROJECTS: { projects: ProjectSummary[] } = {
  projects: [
    {
      id: 'p1',
      title: 'mcp v2 server',
      slug: 'mcp-v2-server',
      status: 'in-progress',
      area: 'backend',
      goal_breadcrumb: { goal_id: 'g1', goal_title: 'mcp rewrite' },
      task_progress: { done: 6, total: 14 },
      staleness_days: 1,
      last_activity_at: null,
    },
    {
      id: 'p2',
      title: 'admin-v2 frontend',
      slug: 'admin-v2-frontend',
      status: 'in-progress',
      area: 'frontend',
      goal_breadcrumb: null,
      task_progress: { done: 8, total: 14 },
      staleness_days: 0,
      last_activity_at: null,
    },
  ],
};

describe('AtlasPageComponent', () => {
  let fixture: ComponentFixture<AtlasPageComponent>;
  let httpMock: HttpTestingController;

  function setupAndLoad(): void {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        provideNoopAnimations(),
      ],
    });
    fixture = TestBed.createComponent(AtlasPageComponent);
    httpMock = TestBed.inject(HttpTestingController);
    fixture.detectChanges();

    httpMock.expectOne('/bff/api/admin/plan/goals').flush(MOCK_GOALS);
    httpMock.expectOne('/bff/api/admin/plan/projects').flush(MOCK_PROJECTS);

    fixture.detectChanges();
  }

  it('should render facet rail and search header', () => {
    setupAndLoad();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid="atlas-facets"]')).toBeTruthy();
    expect(el.querySelector('[data-testid="atlas-search"]')).toBeTruthy();
    httpMock.verify();
  });

  it('should render all loaded entities by default (2 goals + 2 projects)', () => {
    setupAndLoad();
    const rows = fixture.nativeElement.querySelectorAll(
      '[data-testid^="atlas-row-"]',
    );
    expect(rows.length).toBe(4);
    httpMock.verify();
  });

  it('should filter results by search query', () => {
    setupAndLoad();
    const input = fixture.nativeElement.querySelector(
      '[data-testid="atlas-search"]',
    ) as HTMLInputElement;
    input.value = 'studio';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();

    const rows = fixture.nativeElement.querySelectorAll(
      '[data-testid^="atlas-row-"]',
    );
    expect(rows.length).toBe(1);
    expect(rows[0].textContent).toContain('koopa studio launch');
    httpMock.verify();
  });

  it('should toggle type facet to hide goals', () => {
    setupAndLoad();
    const goalFacet = fixture.nativeElement.querySelector(
      '[data-testid="facet-goal"]',
    ) as HTMLButtonElement;
    goalFacet.click();
    fixture.detectChanges();

    const rows = fixture.nativeElement.querySelectorAll(
      '[data-testid^="atlas-row-"]',
    ) as NodeListOf<HTMLElement>;
    expect(rows.length).toBe(2);
    Array.from(rows).forEach((row) => {
      expect(row.getAttribute('data-testid')).toBe('atlas-row-project');
    });
    httpMock.verify();
  });

  it('should produce inspector-targeted hrefs for each row', () => {
    setupAndLoad();
    const rows = fixture.nativeElement.querySelectorAll(
      '[data-testid^="atlas-row-"]',
    ) as NodeListOf<HTMLAnchorElement>;
    const hrefs = Array.from(rows).map((r) => r.getAttribute('href'));
    // Anchors include the inspect query param for each entity
    expect(hrefs.some((h) => h?.includes('inspect=goal:g1'))).toBe(true);
    expect(hrefs.some((h) => h?.includes('inspect=project:p1'))).toBe(true);
    httpMock.verify();
  });

  it('should show empty state for no matches', () => {
    setupAndLoad();
    const input = fixture.nativeElement.querySelector(
      '[data-testid="atlas-search"]',
    ) as HTMLInputElement;
    input.value = 'nonexistent-needle';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();

    const el = fixture.nativeElement.textContent as string;
    expect(el).toContain('No matches');
    httpMock.verify();
  });
});
