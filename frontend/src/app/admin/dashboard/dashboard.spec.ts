import {
  ComponentFixture,
  TestBed,
  fakeAsync,
  tick,
} from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { DashboardComponent } from './dashboard';
import { ArticleService } from '../../core/services/article.service';
import { ProjectService } from '../../core/services/project/project.service';

describe('DashboardComponent', () => {
  let component: DashboardComponent;
  let fixture: ComponentFixture<DashboardComponent>;
  let articleService: ArticleService;
  let projectService: ProjectService;

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
    articleService = TestBed.inject(ArticleService);
    projectService = TestBed.inject(ProjectService);
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  describe('statistics', () => {
    it('should compute total articles count', () => {
      const total = component['totalArticles']();
      expect(total).toBe(articleService.articleList().length);
    });

    it('should compute published articles count', () => {
      const published = component['publishedArticles']();
      const expected = articleService
        .articleList()
        .filter((a) => a.status === 'published').length;
      expect(published).toBe(expected);
    });

    it('should compute draft articles count', () => {
      const drafts = component['draftArticles']();
      const expected = articleService
        .articleList()
        .filter((a) => a.status === 'draft').length;
      expect(drafts).toBe(expected);
    });

    it('should compute publish rate percentage', () => {
      const rate = component['publishRate']();
      const total = articleService.articleList().length;
      const published = articleService
        .articleList()
        .filter((a) => a.status === 'published').length;
      const expected = total > 0 ? Math.round((published / total) * 100) : 0;
      expect(rate).toBe(expected);
    });

    it('should return recent articles sorted by updatedAt desc', () => {
      const recent = component['recentArticles']();
      expect(recent.length).toBeLessThanOrEqual(5);

      for (let i = 1; i < recent.length; i++) {
        const prevDate = new Date(recent[i - 1].updatedAt).getTime();
        const currDate = new Date(recent[i].updatedAt).getTime();
        expect(prevDate).toBeGreaterThanOrEqual(currDate);
      }
    });
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

    it('should delete article and close dialog on confirm', fakeAsync(() => {
      const articles = articleService.articleList();
      const targetArticle = articles[0];
      const spy = spyOn(articleService, 'deleteArticle').and.callThrough();

      component['requestDeleteArticle'](targetArticle.id, targetArticle.title);
      component['confirmDelete']();

      expect(component['isDeleting']()).toBe(true);
      tick(800);

      expect(spy).toHaveBeenCalledWith(targetArticle.id);
      expect(component['isDeleting']()).toBe(false);
      expect(component['deleteTarget']()).toBeNull();
    }));

    it('should delete project and close dialog on confirm', fakeAsync(() => {
      const projects = projectService.allProjects();
      const targetProject = projects[0];
      const spy = spyOn(projectService, 'deleteProject').and.callThrough();

      component['requestDeleteProject'](targetProject.id, targetProject.title);
      component['confirmDelete']();

      expect(component['isDeleting']()).toBe(true);
      tick(500);

      expect(spy).toHaveBeenCalledWith(targetProject.id);
      expect(component['isDeleting']()).toBe(false);
      expect(component['deleteTarget']()).toBeNull();
    }));

    it('should do nothing when confirming without target', () => {
      component['deleteTarget'].set(null);
      component['confirmDelete']();
      expect(component['isDeleting']()).toBe(false);
    });
  });

  describe('status helpers', () => {
    it('should return correct article status labels', () => {
      expect(component['getStatusLabel']('published')).toBe('已發布');
      expect(component['getStatusLabel']('draft')).toBe('草稿');
      expect(component['getStatusLabel']('archived')).toBe('封存');
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

  describe('template rendering', () => {
    it('should display stat cards', () => {
      const text = fixture.nativeElement.textContent;
      expect(text).toContain('總文章數');
      expect(text).toContain('已發布');
      expect(text).toContain('草稿');
    });

    it('should display projects section', () => {
      const text = fixture.nativeElement.textContent;
      expect(text).toContain('專案管理');
    });

    it('should display articles list', () => {
      const text = fixture.nativeElement.textContent;
      expect(text).toContain('最近更新的文章');
    });

    it('should have link to create new article', () => {
      const links = Array.from(
        fixture.nativeElement.querySelectorAll('a'),
      ) as HTMLAnchorElement[];
      const newArticleLink = links.find((l) =>
        l.getAttribute('href')?.includes('/admin/editor'),
      );
      expect(newArticleLink).toBeTruthy();
    });

    it('should have link to create new project', () => {
      const links = Array.from(
        fixture.nativeElement.querySelectorAll('a'),
      ) as HTMLAnchorElement[];
      const newProjectLink = links.find((l) =>
        l.getAttribute('href')?.includes('/admin/project-editor'),
      );
      expect(newProjectLink).toBeTruthy();
    });
  });
});
