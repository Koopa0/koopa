import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { AtlasPageComponent } from './atlas-page.component';
import { InspectorService } from '../inspector/inspector.service';
import type {
  GoalsOverview,
  ProjectSummary,
} from '../../core/models/admin.model';

const MOCK_GOALS: GoalsOverview = {
  state: 'ok',
  goals: [
    {
      id: 'g1',
      title: 'mcp rewrite',
      area_name: 'backend',
      status: 'in_progress',
      milestones_total: 7,
      milestones_done: 4,
      quarter: '2026-Q2',
    },
    {
      id: 'g2',
      title: 'koopa studio launch',
      area_name: 'studio',
      status: 'in_progress',
      milestones_total: 3,
      milestones_done: 1,
      quarter: '2026-Q2',
    },
  ],
};

const MOCK_PROJECTS: { projects: ProjectSummary[] } = {
  projects: [
    {
      id: 'p1',
      title: 'mcp v2 server',
      slug: 'mcp-v2-server',
      status: 'in_progress',
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
      status: 'in_progress',
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

  afterAll(() => TestBed.resetTestingModule());

  async function setupAndLoad(): Promise<void> {
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

    httpMock.expectOne('/bff/api/admin/commitment/goals').flush(MOCK_GOALS);
    httpMock.expectOne('/bff/api/admin/commitment/projects').flush(MOCK_PROJECTS);
    httpMock
      .expectOne((r) => r.url.includes('/bff/api/admin/knowledge/content'))
      .flush({ data: [] });

    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  }

  it('should render facet rail and search header', async () => {
    await setupAndLoad();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid="atlas-facets"]')).toBeTruthy();
    expect(el.querySelector('[data-testid="atlas-search"]')).toBeTruthy();
    httpMock.verify();
  });

  it('should render all loaded entities by default (2 goals + 2 projects)', async () => {
    await setupAndLoad();
    const rows = fixture.nativeElement.querySelectorAll(
      '[data-testid^="atlas-row-"]',
    );
    expect(rows.length).toBe(4);
    httpMock.verify();
  });

  it('should filter results by search query', async () => {
    await setupAndLoad();
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

  it('should toggle type facet to hide goals', async () => {
    await setupAndLoad();
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

  it('should open inspector with correct target when row is clicked', async () => {
    await setupAndLoad();
    const inspector = TestBed.inject(InspectorService);
    const openSpy = vi
      .spyOn(inspector, 'open')
      .mockImplementation(() => undefined);

    const goalRow = fixture.nativeElement.querySelector(
      '[data-testid="atlas-row-goal"]',
    ) as HTMLButtonElement;
    goalRow.click();
    expect(openSpy).toHaveBeenCalledWith({ type: 'goal', id: 'g1' });

    const projectRow = fixture.nativeElement.querySelector(
      '[data-testid="atlas-row-project"]',
    ) as HTMLButtonElement;
    projectRow.click();
    expect(openSpy).toHaveBeenCalledWith({ type: 'project', id: 'p1' });

    httpMock.verify();
  });

  it('should show empty state for no matches', async () => {
    await setupAndLoad();
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
