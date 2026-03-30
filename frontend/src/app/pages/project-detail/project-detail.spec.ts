import { ComponentFixture, TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { ProjectDetailComponent } from './project-detail';
import type { ApiProject } from '../../core/models';

function createMockProject(overrides: Partial<ApiProject> = {}): ApiProject {
  return {
    id: '1',
    slug: 'test-project',
    title: 'Test Project',
    description: 'A test project description',
    long_description: null,
    role: 'Full-stack Developer',
    tech_stack: ['Angular', 'Go'],
    highlights: ['Built from scratch'],
    problem: null,
    solution: null,
    architecture: null,
    results: null,
    github_url: null,
    live_url: null,
    featured: false,
    public: true,
    sort_order: 0,
    status: 'completed',
    notion_page_id: null,
    repo: null,
    area: '',
    deadline: null,
    last_activity_at: null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

describe('ProjectDetailComponent', () => {
  let component: ProjectDetailComponent;
  let fixture: ComponentFixture<ProjectDetailComponent>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ProjectDetailComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        provideNoopAnimations(),
      ],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(ProjectDetailComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should create', () => {
    fixture.componentRef.setInput('slug', 'test-project');
    fixture.detectChanges();
    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/projects/test-project'),
    );
    req.flush({ data: createMockProject() });
    expect(component).toBeTruthy();
  });

  it('should load project when slug provided', () => {
    fixture.componentRef.setInput('slug', 'test-project');
    fixture.detectChanges();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/projects/test-project'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: createMockProject() });

    expect(component['project']()).toBeTruthy();
    expect(component['project']()!.title).toBe('Test Project');
    expect(component['isLoading']()).toBe(false);
  });

  it('should handle HTTP error', () => {
    fixture.componentRef.setInput('slug', 'bad-slug');
    fixture.detectChanges();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/projects/bad-slug'),
    );
    req.flush('Not Found', { status: 404, statusText: 'Not Found' });

    expect(component['isNotFound']()).toBe(true);
    expect(component['isLoading']()).toBe(false);
  });
});
