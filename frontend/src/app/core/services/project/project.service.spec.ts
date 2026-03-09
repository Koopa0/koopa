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
    sort_order: 0,
    status: 'in-progress',
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

  it('should have loading signal initialized to false', () => {
    expect(service.loading()).toBe(false);
  });

  it('should have errorMessage signal initialized to null', () => {
    expect(service.errorMessage()).toBeNull();
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

    it('should set loading to true when called and false after response', () => {
      service.getAllProjects().subscribe();
      expect(service.loading()).toBe(true);

      const req = httpMock.expectOne((r) => r.url.includes('/api/projects'));
      req.flush({ data: [] });

      expect(service.loading()).toBe(false);
    });

    it('should set error message on failure', () => {
      service.getAllProjects().subscribe({
        error: () => {
          // expected
        },
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/projects'));
      req.flush('Server error', { status: 500, statusText: 'Internal Server Error' });

      expect(service.loading()).toBe(false);
      expect(service.errorMessage()).toBe('Failed to load projects');
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

    it('should set loading state during request', () => {
      service.getProjectBySlug('test').subscribe();
      expect(service.loading()).toBe(true);

      const req = httpMock.expectOne((r) => r.url.includes('/api/projects/test'));
      req.flush({ data: createMockProject() });

      expect(service.loading()).toBe(false);
    });

    it('should set error on failure', () => {
      service.getProjectBySlug('not-found').subscribe({
        error: () => {
          // expected
        },
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/projects/not-found'),
      );
      req.flush('Not found', { status: 404, statusText: 'Not Found' });

      expect(service.errorMessage()).toBe('Project not found');
      expect(service.loading()).toBe(false);
    });
  });

  describe('createProject', () => {
    it('should POST to admin projects endpoint', () => {
      const request = {
        slug: 'new-project',
        title: 'New Project',
        description: 'A new project',
        role: 'Developer',
      };
      const mockResponse = createMockProject({ slug: 'new-project', title: 'New Project' });

      service.createProject(request).subscribe((project) => {
        expect(project.title).toBe('New Project');
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/admin/projects'));
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual(request);
      req.flush({ data: mockResponse });
    });
  });

  describe('updateProject', () => {
    it('should PUT to admin projects endpoint with id', () => {
      const mockResponse = createMockProject({ title: 'Updated Title' });

      service.updateProject('proj-001', { title: 'Updated Title' }).subscribe((project) => {
        expect(project.title).toBe('Updated Title');
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/admin/projects/proj-001'),
      );
      expect(req.request.method).toBe('PUT');
      req.flush({ data: mockResponse });
    });
  });

  describe('deleteProject', () => {
    it('should DELETE admin projects endpoint with id', () => {
      service.deleteProject('proj-001').subscribe();

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/admin/projects/proj-001'),
      );
      expect(req.request.method).toBe('DELETE');
      req.flush(null);
    });
  });
});
