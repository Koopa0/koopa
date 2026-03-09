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

    it('should display "新增專案" in title', () => {
      const title = fixture.nativeElement.querySelector('h1');
      expect(title.textContent).toContain('新增專案');
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
      expect(notification!.message).toContain('必要欄位');
    });

    it('should require title with minimum 2 characters', () => {
      const titleControl = component['projectForm'].get('title');
      titleControl?.setValue('');
      titleControl?.markAsTouched();

      expect(titleControl?.invalid).toBe(true);
      expect(component['getFieldError']('title')).toBe('此欄位為必填');

      titleControl?.setValue('A');
      expect(titleControl?.invalid).toBe(true);
      expect(component['getFieldError']('title')).toContain('至少需要 2');

      titleControl?.setValue('AB');
      expect(titleControl?.invalid).toBe(false);
    });

    it('should require description with max 300 characters', () => {
      const descControl = component['projectForm'].get('description');
      descControl?.setValue('A'.repeat(301));
      descControl?.markAsTouched();

      expect(descControl?.invalid).toBe(true);
      expect(component['getFieldError']('description')).toContain('最多 300');
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
      component['newHighlight'].set('亮點一');
      component['addHighlight']();
      component['newHighlight'].set('亮點二');
      component['addHighlight']();

      component['removeHighlight'](0);
      expect(component['highlights']).toEqual(['亮點二']);
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

    it('should display "編輯專案" in title', () => {
      const title = fixture.nativeElement.querySelector('h1');
      expect(title.textContent).toContain('編輯專案');
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

      // 驗證 project 確實更新了
      const updated = projectService.getProjectById(existingProjectId);
      expect(updated!.title).toBe('Updated Title');
    }));

    it('should show submit button text as "更新專案"', () => {
      const buttons = Array.from(
        fixture.nativeElement.querySelectorAll('button[type="submit"]'),
      ) as HTMLElement[];
      const submitBtn = buttons.find((b) =>
        b.textContent?.includes('更新專案'),
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
      component['newHighlight'].set('自動化部署');
      const event = new KeyboardEvent('keydown', { key: 'Enter' });
      spyOn(event, 'preventDefault');

      component['onHighlightKeydown'](event);

      expect(event.preventDefault).toHaveBeenCalled();
      expect(component['highlights']).toEqual(['自動化部署']);
    });

    it('should not add tech on non-Enter key', () => {
      component['newTech'].set('React');
      const event = new KeyboardEvent('keydown', { key: 'Tab' });

      component['onTechKeydown'](event);

      expect(component['techStack']).toEqual([]);
    });
  });
});
