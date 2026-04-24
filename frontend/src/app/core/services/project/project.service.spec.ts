import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { ProjectService } from './project.service';
import type { ApiProject } from '../../models';

function createMockProject(overrides: Partial<ApiProject> = {}): ApiProject {
  return {
    id: 'proj-001',
    slug: 'test-project',
    title: 'Test Project',
    description: 'A test project',
    long_description: null,
    role: 'Developer',
    tech_stack: ['Angular', 'Go'],
    highlights: ['Feature A'],
    problem: null,
    solution: null,
    architecture: null,
    results: null,
    github_url: null,
    live_url: null,
    featured: false,
    is_public: true,
    sort_order: 0,
    status: 'in_progress',
    repo: null,
    area: '',
    deadline: null,
    last_activity_at: null,
    created_at: '2026-01-10T10:00:00Z',
    updated_at: '2026-01-15T10:00:00Z',
    ...overrides,
  };
}

describe('ProjectService', () => {
  let service: ProjectService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ProjectService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('getAllProjects', () => {
    it('should fetch all projects', () => {
      const mockProjects = [
        createMockProject({ id: 'proj-001', slug: 'project-a' }),
        createMockProject({ id: 'proj-002', slug: 'project-b' }),
      ];

      service.getAllProjects().subscribe((projects) => {
        expect(projects.length).toBe(2);
        expect(projects).toEqual(mockProjects);
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/projects'));
      expect(req.request.method).toBe('GET');
      req.flush({ data: mockProjects });
    });

    it('should propagate error to subscriber', () => {
      service.getAllProjects().subscribe({
        error: (err) => {
          expect(err).toBeTruthy();
        },
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/projects'));
      req.flush('Server error', {
        status: 500,
        statusText: 'Internal Server Error',
      });
    });
  });

  describe('getProjectBySlug', () => {
    it('should fetch a single project by slug', () => {
      const mockProject = createMockProject({ slug: 'my-project' });

      service.getProjectBySlug('my-project').subscribe((project) => {
        expect(project).toEqual(mockProject);
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/projects/my-project'),
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: mockProject });
    });

    it('should propagate error to subscriber on failure', () => {
      service.getProjectBySlug('not-found').subscribe({
        error: (err) => {
          expect(err).toBeTruthy();
        },
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/projects/not-found'),
      );
      req.flush('Not found', { status: 404, statusText: 'Not Found' });
    });
  });
});
