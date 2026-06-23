import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
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
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
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

  describe('getAdminProjects', () => {
    it('should fetch admin projects from the commitment endpoint', () => {
      const mockProjects = [
        createMockProject({ id: 'proj-001', slug: 'project-a' }),
        createMockProject({ id: 'proj-002', slug: 'project-b' }),
      ];

      let received: ApiProject[] = [];
      service.getAdminProjects().subscribe((projects) => {
        received = projects;
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/admin/commitment/projects'),
      );
      expect(req.request.method).toBe('GET');
      req.flush({ data: mockProjects });

      expect(received).toEqual(mockProjects);
    });

    it('should propagate error to subscriber', () => {
      let captured: unknown;
      service.getAdminProjects().subscribe({
        error: (err) => {
          captured = err;
        },
      });

      const req = httpMock.expectOne((r) =>
        r.url.includes('/api/admin/commitment/projects'),
      );
      req.flush('Server error', {
        status: 500,
        statusText: 'Internal Server Error',
      });

      expect(captured).toBeTruthy();
    });
  });
});
