import {
  ComponentFixture,
  TestBed,
  fakeAsync,
  tick,
} from '@angular/core/testing';
import { provideRouter, ActivatedRoute, Router } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { ProjectEditorComponent } from './project-editor';
import { ProjectService } from '../../core/services/project/project.service';

describe('ProjectEditorComponent', () => {
  let component: ProjectEditorComponent;
  let fixture: ComponentFixture<ProjectEditorComponent>;
  let router: Router;
  let projectService: ProjectService;

  function createComponent(projectId: string | null) {
    TestBed.overrideProvider(ActivatedRoute, {
      useValue: {
        snapshot: {
          paramMap: {
            get: (key: string) => (key === 'id' ? projectId : null),
          },
        },
      },
    });

    fixture = TestBed.createComponent(ProjectEditorComponent);
    component = fixture.componentInstance;
    router = TestBed.inject(Router);
    projectService = TestBed.inject(ProjectService);
  }

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ProjectEditorComponent],
      providers: [
        provideRouter([]),
        { provide: PLATFORM_ID, useValue: 'browser' },
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: {
              paramMap: { get: () => null },
            },
          },
        },
      ],
    }).compileComponents();
  });

  describe('create mode', () => {
    beforeEach(() => {
      createComponent(null);
      fixture.detectChanges();
    });

    it('should create', () => {
      expect(component).toBeTruthy();
    });

    it('should be in new project mode', () => {
      expect(component['isNewProject']()).toBe(true);
    });

    it('should display "New Project" in title', () => {
      const title = fixture.nativeElement.querySelector('h1');
      expect(title.textContent).toContain('New Project');
    });

    it('should have an empty form initially', () => {
      const form = component['projectForm'];
      expect(form.get('title')?.value).toBe('');
      expect(form.get('slug')?.value).toBe('');
      expect(form.get('description')?.value).toBe('');
      expect(form.get('techStack')?.value).toEqual([]);
      expect(form.get('highlights')?.value).toEqual([]);
    });

    it('should show validation errors when saving with empty required fields', () => {
      component['save']();
      fixture.detectChanges();

      const notification = component['notification']();
      expect(notification).toBeTruthy();
      expect(notification!.type).toBe('error');
      expect(notification!.message).toContain('required fields');
    });

    it('should require title with minimum 2 characters', () => {
      const titleControl = component['projectForm'].get('title');
      titleControl?.setValue('');
      titleControl?.markAsTouched();

      expect(titleControl?.invalid).toBe(true);
      expect(component['getFieldError']('title')).toBe('This field is required');

      titleControl?.setValue('A');
      expect(titleControl?.invalid).toBe(true);
      expect(component['getFieldError']('title')).toContain('Must be at least 2');

      titleControl?.setValue('AB');
      expect(titleControl?.invalid).toBe(false);
    });

    it('should require description with max 300 characters', () => {
      const descControl = component['projectForm'].get('description');
      descControl?.setValue('A'.repeat(301));
      descControl?.markAsTouched();

      expect(descControl?.invalid).toBe(true);
      expect(component['getFieldError']('description')).toContain('Must be at most 300');
    });

    it('should add tech stack item', () => {
      component['newTech'].set('Angular');
      component['addTech']();

      expect(component['techStack']).toEqual(['Angular']);
      expect(component['newTech']()).toBe('');
    });

    it('should not add duplicate tech stack item', () => {
      component['newTech'].set('Angular');
      component['addTech']();
      component['newTech'].set('Angular');
      component['addTech']();

      expect(component['techStack']).toEqual(['Angular']);
    });

    it('should not add empty tech stack item', () => {
      component['newTech'].set('  ');
      component['addTech']();

      expect(component['techStack']).toEqual([]);
    });

    it('should remove tech stack item', () => {
      component['newTech'].set('Angular');
      component['addTech']();
      component['newTech'].set('TypeScript');
      component['addTech']();

      component['removeTech']('Angular');
      expect(component['techStack']).toEqual(['TypeScript']);
    });

    it('should add highlight item', () => {
      component['newHighlight'].set('SSR 支援');
      component['addHighlight']();

      expect(component['highlights']).toEqual(['SSR 支援']);
      expect(component['newHighlight']()).toBe('');
    });

    it('should remove highlight by index', () => {
      component['newHighlight'].set('Highlight 1');
      component['addHighlight']();
      component['newHighlight'].set('Highlight 2');
      component['addHighlight']();

      component['removeHighlight'](0);
      expect(component['highlights']).toEqual(['Highlight 2']);
    });

    it('should create project and navigate to admin on save', fakeAsync(() => {
      const navigateSpy = spyOn(router, 'navigate');

      component['projectForm'].patchValue({
        title: 'Test Project',
        slug: 'test-project',
        description: 'A test project description',
        role: 'Developer',
        status: 'in-progress',
      });

      component['save']();
      expect(component['isSaving']()).toBe(true);

      tick(500);

      expect(component['isSaving']()).toBe(false);
      expect(navigateSpy).toHaveBeenCalledWith(['/admin']);
    }));

    it('should navigate to admin on cancel', () => {
      const navigateSpy = spyOn(router, 'navigate');
      component['cancel']();
      expect(navigateSpy).toHaveBeenCalledWith(['/admin']);
    });
  });

  describe('edit mode', () => {
    const existingProjectId = 'proj-001';

    beforeEach(() => {
      createComponent(existingProjectId);
      fixture.detectChanges();
    });

    it('should be in edit mode', () => {
      expect(component['isNewProject']()).toBe(false);
    });

    it('should display "Edit Project" in title', () => {
      const title = fixture.nativeElement.querySelector('h1');
      expect(title.textContent).toContain('Edit Project');
    });

    it('should populate form with existing project data', () => {
      const project = projectService.getProjectById(existingProjectId);
      const form = component['projectForm'];

      expect(form.get('title')?.value).toBe(project!.title);
      expect(form.get('slug')?.value).toBe(project!.slug);
      expect(form.get('description')?.value).toBe(project!.description);
      expect(form.get('techStack')?.value).toEqual(project!.techStack);
      expect(form.get('role')?.value).toBe(project!.role);
      expect(form.get('status')?.value).toBe(project!.status);
    });

    it('should update project and navigate to admin on save', fakeAsync(() => {
      const navigateSpy = spyOn(router, 'navigate');

      component['projectForm'].patchValue({
        title: 'Updated Title',
      });

      component['save']();
      expect(component['isSaving']()).toBe(true);

      tick(500);

      expect(component['isSaving']()).toBe(false);
      expect(navigateSpy).toHaveBeenCalledWith(['/admin']);

      // Verify the project was actually updated
      const updated = projectService.getProjectById(existingProjectId);
      expect(updated!.title).toBe('Updated Title');
    }));

    it('should show submit button text as "Update Project"', () => {
      const buttons = Array.from(
        fixture.nativeElement.querySelectorAll('button[type="submit"]'),
      ) as HTMLElement[];
      const submitBtn = buttons.find((b) =>
        b.textContent?.includes('Update Project'),
      );
      expect(submitBtn).toBeTruthy();
    });
  });

  describe('keyboard interactions', () => {
    beforeEach(() => {
      createComponent(null);
      fixture.detectChanges();
    });

    it('should add tech on Enter key', () => {
      component['newTech'].set('React');
      const event = new KeyboardEvent('keydown', { key: 'Enter' });
      spyOn(event, 'preventDefault');

      component['onTechKeydown'](event);

      expect(event.preventDefault).toHaveBeenCalled();
      expect(component['techStack']).toEqual(['React']);
    });

    it('should add highlight on Enter key', () => {
      component['newHighlight'].set('Automated deployment');
      const event = new KeyboardEvent('keydown', { key: 'Enter' });
      spyOn(event, 'preventDefault');

      component['onHighlightKeydown'](event);

      expect(event.preventDefault).toHaveBeenCalled();
      expect(component['highlights']).toEqual(['Automated deployment']);
    });

    it('should not add tech on non-Enter key', () => {
      component['newTech'].set('React');
      const event = new KeyboardEvent('keydown', { key: 'Tab' });

      component['onTechKeydown'](event);

      expect(component['techStack']).toEqual([]);
    });
  });
});
