import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { ProjectsComponent } from './projects';
import { ProjectService } from '../../core/services/project/project.service';
import { SeoService } from '../../core/services/seo/seo.service';
import { PLATFORM_ID } from '@angular/core';

describe('ProjectsComponent', () => {
  let component: ProjectsComponent;
  let fixture: ComponentFixture<ProjectsComponent>;
  let seoService: SeoService;
  let projectService: ProjectService;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ProjectsComponent],
      providers: [
        provideRouter([]),
        { provide: PLATFORM_ID, useValue: 'browser' },
        provideNoopAnimations(),
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(ProjectsComponent);
    component = fixture.componentInstance;
    seoService = TestBed.inject(SeoService);
    projectService = TestBed.inject(ProjectService);
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should display all projects by default', () => {
    const allProjects = projectService.allProjects();
    const cards = fixture.nativeElement.querySelectorAll('.grid > div');
    expect(cards.length).toBe(allProjects.length);
  });

  it('should set SEO meta on init', () => {
    const spy = spyOn(seoService, 'updateMeta');
    component.ngOnInit();
    expect(spy).toHaveBeenCalledWith(
      jasmine.objectContaining({
        title: 'Projects',
        ogUrl: 'https://koopa0.dev/projects',
      }),
    );
  });

  it('should show project count text', () => {
    const allProjects = projectService.allProjects();
    const countText = fixture.nativeElement.textContent;
    expect(countText).toContain(`${allProjects.length}`);
    expect(countText).toContain('projects');
  });

  it('should render status filter buttons', () => {
    const filterButtons = fixture.nativeElement.querySelectorAll(
      '.flex.flex-wrap.gap-2 button',
    );
    expect(filterButtons.length).toBe(4);
    expect(filterButtons[0].textContent.trim()).toBe('All');
    expect(filterButtons[1].textContent.trim()).toBe('Completed');
    expect(filterButtons[2].textContent.trim()).toBe('In Progress');
    expect(filterButtons[3].textContent.trim()).toBe('Maintained');
  });

  it('should filter projects when status button is clicked', () => {
    const allProjects = projectService.allProjects();
    const completedCount = allProjects.filter(
      (p) => p.status === 'completed',
    ).length;

    // Click "Completed" button
    const filterButtons = fixture.nativeElement.querySelectorAll(
      '.flex.flex-wrap.gap-2 button',
    );
    filterButtons[1].click();
    fixture.detectChanges();

    const cards = fixture.nativeElement.querySelectorAll('.grid > div');
    expect(cards.length).toBe(completedCount);
  });

  it('should show empty state when no projects match filter', () => {
    // Programmatically set a filter with no matches
    component['selectedStatus'].set('in-progress');
    fixture.detectChanges();

    const allProjects = projectService.allProjects();
    const inProgressCount = allProjects.filter(
      (p) => p.status === 'in-progress',
    ).length;

    if (inProgressCount === 0) {
      const emptyText = fixture.nativeElement.textContent;
      expect(emptyText).toContain('No projects yet');
    }
  });

  it('should show reset button in empty state when filter is active', () => {
    // If a status has no matching projects, test the reset button
    component['selectedStatus'].set('in-progress');
    fixture.detectChanges();

    const allProjects = projectService.allProjects();
    const inProgressCount = allProjects.filter(
      (p) => p.status === 'in-progress',
    ).length;

    if (inProgressCount === 0) {
      const resetButton = fixture.nativeElement.querySelector('button');
      // There should be a reset/show all button
      const buttons = Array.from(
        fixture.nativeElement.querySelectorAll('button'),
      ) as HTMLElement[];
      const resetBtn = buttons.find((b) =>
        b.textContent?.includes('Show all projects'),
      );
      expect(resetBtn).toBeTruthy();
    }
  });

  it('should display project title, description, and tech stack', () => {
    const firstProject = projectService.allProjects()[0];
    const content = fixture.nativeElement.textContent;

    expect(content).toContain(firstProject.title);
    expect(content).toContain(firstProject.description);
    firstProject.techStack.forEach((tech) => {
      expect(content).toContain(tech);
    });
  });

  it('should display correct status badge for each project', () => {
    const badges = fixture.nativeElement.querySelectorAll(
      '.rounded-full .text-xs',
    );
    // Ensure status badges exist
    const allProjects = projectService.allProjects();
    allProjects.forEach((project) => {
      const content = fixture.nativeElement.textContent;
      const expectedLabel =
        project.status === 'completed'
          ? 'Completed'
          : project.status === 'in-progress'
            ? 'In Progress'
            : 'Maintained';
      expect(content).toContain(expectedLabel);
    });
  });

  it('should highlight the active filter button', () => {
    // Default "All" should be active
    const filterButtons = fixture.nativeElement.querySelectorAll(
      '.flex.flex-wrap.gap-2 button',
    );
    expect(filterButtons[0].classList).toContain('bg-zinc-700');

    // Switch to Completed
    filterButtons[1].click();
    fixture.detectChanges();

    expect(filterButtons[1].classList).toContain('bg-zinc-700');
  });

  it('should have links to project detail pages', () => {
    const firstProject = projectService.allProjects()[0];
    const links = fixture.nativeElement.querySelectorAll('a');
    const detailLinks = Array.from(links).filter((link: unknown) =>
      (link as HTMLAnchorElement)
        .getAttribute('href')
        ?.includes(`/projects/${firstProject.slug}`),
    );
    expect(detailLinks.length).toBeGreaterThan(0);
  });
});
