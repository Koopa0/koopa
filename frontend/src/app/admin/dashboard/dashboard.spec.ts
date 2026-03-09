import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { DashboardComponent } from './dashboard';

describe('DashboardComponent', () => {
  let component: DashboardComponent;
  let fixture: ComponentFixture<DashboardComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [DashboardComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: PLATFORM_ID, useValue: 'browser' },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(DashboardComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  describe('delete confirmation dialog', () => {
    it('should not show delete dialog initially', () => {
      expect(component['deleteTarget']()).toBeNull();
    });

    it('should open article delete dialog with correct data', () => {
      component['requestDeleteArticle']('art-1', 'Test Article');

      expect(component['deleteTarget']()).toEqual({
        id: 'art-1',
        title: 'Test Article',
      });
      expect(component['deleteType']()).toBe('article');
    });

    it('should open project delete dialog with correct data', () => {
      component['requestDeleteProject']('proj-1', 'Test Project');

      expect(component['deleteTarget']()).toEqual({
        id: 'proj-1',
        title: 'Test Project',
      });
      expect(component['deleteType']()).toBe('project');
    });

    it('should close dialog on cancel', () => {
      component['requestDeleteArticle']('art-1', 'Test');
      expect(component['deleteTarget']()).not.toBeNull();

      component['cancelDelete']();
      expect(component['deleteTarget']()).toBeNull();
    });

    it('should do nothing when confirming without target', () => {
      component['deleteTarget'].set(null);
      component['confirmDelete']();
      expect(component['isDeleting']()).toBe(false);
    });
  });

  describe('status helpers', () => {
    it('should return correct article status labels', () => {
      expect(component['getStatusLabel']('published')).toBe('Published');
      expect(component['getStatusLabel']('draft')).toBe('Draft');
      expect(component['getStatusLabel']('archived')).toBe('Archived');
      expect(component['getStatusLabel']('unknown')).toBe('unknown');
    });

    it('should return correct article status CSS classes', () => {
      expect(component['getStatusClass']('published')).toContain('emerald');
      expect(component['getStatusClass']('draft')).toContain('amber');
      expect(component['getStatusClass']('archived')).toContain('zinc');
    });

    it('should return correct project status labels', () => {
      expect(component['getProjectStatusLabel']('completed')).toBe('Completed');
      expect(component['getProjectStatusLabel']('in-progress')).toBe(
        'In Progress',
      );
      expect(component['getProjectStatusLabel']('maintained')).toBe(
        'Maintained',
      );
    });

    it('should return correct project status CSS classes', () => {
      expect(component['getProjectStatusClass']('completed')).toContain(
        'emerald',
      );
      expect(component['getProjectStatusClass']('in-progress')).toContain(
        'amber',
      );
      expect(component['getProjectStatusClass']('maintained')).toContain('sky');
    });
  });
});
