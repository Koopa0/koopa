import { TestBed, fakeAsync, tick } from '@angular/core/testing';
import { ProjectService } from './project.service';
import { CreateProjectRequest } from '../../models/project.model';

describe('ProjectService', () => {
  let service: ProjectService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(ProjectService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('read operations', () => {
    it('should return all projects', () => {
      const projects = service.allProjects();
      expect(projects.length).toBeGreaterThan(0);
    });

    it('should return only featured projects sorted by order', () => {
      const featured = service.featuredProjects();
      expect(featured.length).toBeGreaterThan(0);
      expect(featured.every((p) => p.featured)).toBe(true);

      for (let i = 1; i < featured.length; i++) {
        expect(featured[i].order).toBeGreaterThanOrEqual(featured[i - 1].order);
      }
    });

    it('should find project by slug', () => {
      const all = service.allProjects();
      const first = all[0];
      const found = service.getProjectBySlug(first.slug);
      expect(found).toBeDefined();
      expect(found!.id).toBe(first.id);
    });

    it('should return undefined for unknown slug', () => {
      const found = service.getProjectBySlug('non-existent-slug');
      expect(found).toBeUndefined();
    });

    it('should find project by id', () => {
      const all = service.allProjects();
      const first = all[0];
      const found = service.getProjectById(first.id);
      expect(found).toBeDefined();
      expect(found!.slug).toBe(first.slug);
    });

    it('should return undefined for unknown id', () => {
      const found = service.getProjectById('non-existent-id');
      expect(found).toBeUndefined();
    });
  });

  describe('createProject', () => {
    const newProject: CreateProjectRequest = {
      title: 'New Test Project',
      slug: 'new-test-project',
      description: 'A project for testing',
      techStack: ['Angular', 'TypeScript'],
      role: 'Developer',
      highlights: ['Feature A', 'Feature B'],
      featured: false,
      order: 10,
      status: 'in-progress',
    };

    it('should add a new project to the list', fakeAsync(() => {
      const initialCount = service.allProjects().length;

      service.createProject(newProject).subscribe();
      tick(500);

      expect(service.allProjects().length).toBe(initialCount + 1);
    }));

    it('should return the created project with generated id', fakeAsync(() => {
      let created: unknown;
      service.createProject(newProject).subscribe((p) => {
        created = p;
      });
      tick(500);

      expect(created).toBeDefined();
      expect((created as { id: string }).id).toBeTruthy();
      expect((created as { title: string }).title).toBe(newProject.title);
    }));

    it('should make newly created project findable by id', fakeAsync(() => {
      let createdId = '';
      service.createProject(newProject).subscribe((p) => {
        createdId = p.id;
      });
      tick(500);

      const found = service.getProjectById(createdId);
      expect(found).toBeDefined();
      expect(found!.title).toBe(newProject.title);
    }));
  });

  describe('updateProject', () => {
    it('should update existing project fields', fakeAsync(() => {
      const existing = service.allProjects()[0];
      const updatedTitle = 'Updated Title';

      service
        .updateProject({ id: existing.id, title: updatedTitle })
        .subscribe();
      tick(500);

      const updated = service.getProjectById(existing.id);
      expect(updated!.title).toBe(updatedTitle);
      // Other fields should not change
      expect(updated!.slug).toBe(existing.slug);
      expect(updated!.description).toBe(existing.description);
    }));

    it('should return updated project', fakeAsync(() => {
      const existing = service.allProjects()[0];
      let result: unknown;

      service
        .updateProject({ id: existing.id, title: 'New Title' })
        .subscribe((p) => {
          result = p;
        });
      tick(500);

      expect((result as { title: string }).title).toBe('New Title');
    }));

    it('should error when updating non-existent project', fakeAsync(() => {
      let errorCaught = false;

      service.updateProject({ id: 'non-existent-id', title: 'X' }).subscribe({
        error: (err) => {
          errorCaught = true;
          expect(err.message).toContain('not found');
        },
      });
      tick(500);

      expect(errorCaught).toBe(true);
    }));

    it('should not affect other projects in the list', fakeAsync(() => {
      const all = service.allProjects();
      const first = all[0];
      const second = all[1];
      const originalSecondTitle = second.title;

      service.updateProject({ id: first.id, title: 'Changed' }).subscribe();
      tick(500);

      const unchangedSecond = service.getProjectById(second.id);
      expect(unchangedSecond!.title).toBe(originalSecondTitle);
    }));
  });

  describe('deleteProject', () => {
    it('should remove project from list', fakeAsync(() => {
      const initialCount = service.allProjects().length;
      const toDelete = service.allProjects()[0];

      service.deleteProject(toDelete.id).subscribe();
      tick(500);

      expect(service.allProjects().length).toBe(initialCount - 1);
      expect(service.getProjectById(toDelete.id)).toBeUndefined();
    }));

    it('should error when deleting non-existent project', fakeAsync(() => {
      let errorCaught = false;

      service.deleteProject('non-existent-id').subscribe({
        error: (err) => {
          errorCaught = true;
          expect(err.message).toContain('not found');
        },
      });
      tick(500);

      expect(errorCaught).toBe(true);
    }));

    it('should not affect remaining projects', fakeAsync(() => {
      const all = service.allProjects();
      const toDelete = all[0];
      const toKeep = all[1];

      service.deleteProject(toDelete.id).subscribe();
      tick(500);

      const kept = service.getProjectById(toKeep.id);
      expect(kept).toBeDefined();
      expect(kept!.title).toBe(toKeep.title);
    }));

    it('should update featuredProjects after deleting a featured project', fakeAsync(() => {
      const featured = service.featuredProjects();
      const featuredProject = featured[0];
      const initialFeaturedCount = featured.length;

      service.deleteProject(featuredProject.id).subscribe();
      tick(500);

      expect(service.featuredProjects().length).toBe(initialFeaturedCount - 1);
    }));
  });
});
