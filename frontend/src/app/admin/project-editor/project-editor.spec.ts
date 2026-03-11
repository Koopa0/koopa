import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { ProjectEditorComponent } from './project-editor';
import { NotificationService } from '../../core/services/notification.service';

describe('ProjectEditorComponent', () => {
  let component: ProjectEditorComponent;
  let fixture: ComponentFixture<ProjectEditorComponent>;
  let router: Router;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ProjectEditorComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: PLATFORM_ID, useValue: 'browser' },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(ProjectEditorComponent);
    component = fixture.componentInstance;
    router = TestBed.inject(Router);
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should be in new project mode', () => {
    expect(component['isNewProject']()).toBe(true);
  });

  it('should have an empty form initially', () => {
    const form = component['projectForm'];
    expect(form.get('title')?.value).toBe('');
    expect(form.get('slug')?.value).toBe('');
    expect(form.get('description')?.value).toBe('');
    expect(form.get('tech_stack')?.value).toEqual([]);
    expect(form.get('highlights')?.value).toEqual([]);
  });

  it('should show validation errors when saving with empty required fields', () => {
    const notificationService = TestBed.inject(NotificationService);
    const errorSpy = vi.spyOn(notificationService, 'error');
    component['save']();
    fixture.detectChanges();

    expect(errorSpy).toHaveBeenCalledWith('Please fill in all required fields');
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
    component['newHighlight'].set('SSR support');
    component['addHighlight']();

    expect(component['highlights']).toEqual(['SSR support']);
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

  it('should navigate to admin on cancel', () => {
    const navigateSpy = vi.spyOn(router, 'navigate');
    component['cancel']();
    expect(navigateSpy).toHaveBeenCalledWith(['/admin']);
  });

  describe('keyboard interactions', () => {
    it('should add tech on Enter key', () => {
      component['newTech'].set('React');
      const event = new KeyboardEvent('keydown', { key: 'Enter' });
      vi.spyOn(event, 'preventDefault');

      component['onTechKeydown'](event);

      expect(event.preventDefault).toHaveBeenCalled();
      expect(component['techStack']).toEqual(['React']);
    });

    it('should add highlight on Enter key', () => {
      component['newHighlight'].set('Automated deployment');
      const event = new KeyboardEvent('keydown', { key: 'Enter' });
      vi.spyOn(event, 'preventDefault');

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
