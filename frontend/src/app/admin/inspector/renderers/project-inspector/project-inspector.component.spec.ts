import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { ProjectInspectorComponent } from './project-inspector.component';
import type { ProjectDetail } from '../../../../core/models/admin.model';

describe('ProjectInspectorComponent', () => {
  let fixture: ComponentFixture<ProjectInspectorComponent>;
  let httpMock: HttpTestingController;

  const mockProject: ProjectDetail = {
    id: 'p1',
    title: 'studio launch',
    slug: 'studio-launch',
    description: 'Launch Koopa Studio',
    problem: 'Need a recurring revenue stream',
    solution: 'Productize MCP server',
    architecture: null,
    status: 'in-progress',
    area: 'studio',
    goal_breadcrumb: { goal_id: 'g1', goal_title: 'Koopa Studio Launch' },
    tasks_by_status: {
      in_progress: [
        {
          id: 't1',
          title: 'pricing',
          priority: 'high',
          energy: 'high',
          due: null,
          is_in_today_plan: false,
        },
      ],
      todo: [
        {
          id: 't2',
          title: 'landing page',
          priority: 'medium',
          energy: 'medium',
          due: null,
          is_in_today_plan: false,
        },
      ],
      done: [],
      someday: [],
    },
    recent_activity: [
      {
        type: 'task_created',
        title: 'added pricing task',
        timestamp: '2026-04-13T08:00:00Z',
      },
    ],
    related_content: [],
  };

  function setupFixture(): void {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideNoopAnimations(),
      ],
    });
    fixture = TestBed.createComponent(ProjectInspectorComponent);
    httpMock = TestBed.inject(HttpTestingController);
  }

  function flushAll(id: string, response: ProjectDetail | null): void {
    const reqs = httpMock.match(`/bff/api/admin/plan/projects/${id}`);
    expect(reqs.length).toBeGreaterThan(0);
    for (const r of reqs) {
      if (response === null) {
        r.flush(null, { status: 500, statusText: 'Internal Server Error' });
      } else {
        r.flush(response);
      }
    }
  }

  it('should render project title in overview tab', async () => {
    setupFixture();
    fixture.componentRef.setInput('id', 'p1');
    fixture.detectChanges();

    flushAll('p1', mockProject);

    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    const titleEl = fixture.nativeElement.querySelector(
      '[data-testid="project-title"]',
    ) as HTMLElement | null;
    expect(titleEl?.textContent).toContain('studio launch');

    const overview = fixture.nativeElement.querySelector(
      '[data-testid="project-overview-section"]',
    ) as HTMLElement;
    expect(overview).toBeTruthy();
    // Goal breadcrumb rendered
    expect(overview.textContent).toContain('Koopa Studio Launch');
    // Task counts rendered
    expect(overview.textContent).toContain('in progress');

    httpMock.verify();
  });

  it('should render activity section when activeTab is activity', async () => {
    setupFixture();
    fixture.componentRef.setInput('id', 'p1');
    fixture.componentRef.setInput('activeTab', 'activity');
    fixture.detectChanges();

    flushAll('p1', mockProject);

    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    const activity = fixture.nativeElement.querySelector(
      '[data-testid="project-activity-section"]',
    ) as HTMLElement;
    expect(activity).toBeTruthy();
    expect(activity.textContent).toContain('added pricing task');

    const overview = fixture.nativeElement.querySelector(
      '[data-testid="project-overview-section"]',
    );
    expect(overview).toBeNull();

    httpMock.verify();
  });

  it('should render error state when fetch fails', async () => {
    setupFixture();
    fixture.componentRef.setInput('id', 'p1');
    fixture.detectChanges();

    flushAll('p1', null);

    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    const errorEl = fixture.nativeElement.querySelector('[role="alert"]');
    expect(errorEl).toBeTruthy();
    expect(errorEl.textContent).toContain('Failed to load project');

    httpMock.verify();
  });
});
