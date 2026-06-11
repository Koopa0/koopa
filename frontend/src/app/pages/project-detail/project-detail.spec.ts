import { ComponentFixture, TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { Title } from '@angular/platform-browser';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { environment } from '../../../environments/environment';
import { ProjectDetailComponent } from './project-detail';
import type { ApiPortfolioProject, ApiProject } from '../../core/models';

function buildMockListing(
  overrides: Partial<ApiPortfolioProject> = {},
): ApiPortfolioProject {
  return {
    id: '1',
    slug: 'test-project',
    title: 'Test Project',
    description: 'A test project description',
    status: 'completed',
    role: 'Full-stack Developer',
    tech_stack: ['Angular', 'Go'],
    highlights: ['Built from scratch'],
    problem: 'The problem statement',
    featured: false,
    sort_order: 0,
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

function buildMockBareRow(overrides: Partial<ApiProject> = {}): ApiProject {
  return {
    id: '1',
    slug: 'test-project',
    title: 'Test Project',
    description: 'A test project description',
    long_description: null,
    role: '',
    tech_stack: [],
    highlights: [],
    problem: null,
    solution: null,
    architecture: null,
    results: null,
    github_url: null,
    live_url: null,
    featured: false,
    is_public: true,
    sort_order: 0,
    status: 'completed',
    repo: null,
    area: '',
    deadline: null,
    last_activity_at: null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

describe('ProjectDetailComponent', () => {
  let component: ProjectDetailComponent;
  let fixture: ComponentFixture<ProjectDetailComponent>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ProjectDetailComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        provideNoopAnimations(),
      ],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(ProjectDetailComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    httpMock.verify();
  });

  /** Flush effects + microtasks so rxResource issues its requests. */
  async function settle(): Promise<void> {
    fixture.detectChanges();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  function flushPortfolio(listings: ApiPortfolioProject[]): void {
    const req = httpMock.expectOne(
      (r) => r.url.includes('/api/portfolio') && r.method === 'GET',
    );
    req.flush({ data: listings });
  }

  function flushBareRow(slug: string, row: ApiProject | null): void {
    const req = httpMock.expectOne((r) =>
      r.url.includes(`/api/projects/${slug}`),
    );
    if (row) {
      req.flush({ data: row });
    } else {
      req.flush('Not Found', { status: 404, statusText: 'Not Found' });
    }
  }

  it('should create', async () => {
    fixture.componentRef.setInput('slug', 'test-project');
    await settle();
    flushPortfolio([buildMockListing()]);
    flushBareRow('test-project', buildMockBareRow());
    expect(component).toBeTruthy();
  });

  it('should compose the rich profile from the portfolio listing when present', async () => {
    fixture.componentRef.setInput('slug', 'test-project');
    await settle();
    flushPortfolio([buildMockListing()]);
    flushBareRow('test-project', buildMockBareRow());
    await settle();

    const project = component['project']();
    expect(project).toBeTruthy();
    expect(project!.role).toBe('Full-stack Developer');
    expect(project!.problem).toBe('The problem statement');
    expect(project!.tech_stack).toEqual(['Angular', 'Go']);

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('The problem');
    expect(el.textContent).toContain('The problem statement');
  });

  it('should fall back to the bare project row when the portfolio lacks the slug', async () => {
    fixture.componentRef.setInput('slug', 'test-project');
    await settle();
    flushPortfolio([buildMockListing({ slug: 'other-project' })]);
    flushBareRow('test-project', buildMockBareRow());
    await settle();

    const project = component['project']();
    expect(project).toBeTruthy();
    expect(project!.title).toBe('Test Project');
    expect(project!.role).toBeNull();
    expect(project!.highlights).toEqual([]);
    expect(component['isNotFound']()).toBe(false);
  });

  it('should report not found when neither source has the project', async () => {
    fixture.componentRef.setInput('slug', 'bad-slug');
    await settle();
    flushPortfolio([]);
    flushBareRow('bad-slug', null);
    await settle();

    expect(component['isNotFound']()).toBe(true);
    expect(component['isLoading']()).toBe(false);
  });

  it('should set the page title without doubling the site name', async () => {
    fixture.componentRef.setInput('slug', 'test-project');
    await settle();
    flushPortfolio([buildMockListing()]);
    flushBareRow('test-project', buildMockBareRow());
    await settle();

    const title = TestBed.inject(Title).getTitle();
    expect(title).toBe(`Test Project | ${environment.siteName}`);
  });

  it('should emit breadcrumb JSON-LD for the project trail', async () => {
    fixture.componentRef.setInput('slug', 'test-project');
    await settle();
    flushPortfolio([buildMockListing()]);
    flushBareRow('test-project', buildMockBareRow());
    await settle();

    const script = document.querySelector(
      'script[type="application/ld+json"][data-seo]',
    );
    expect(script).toBeTruthy();
    const jsonLd = JSON.parse(script!.textContent ?? '{}') as {
      '@type': string;
      itemListElement: { name: string }[];
    };
    expect(jsonLd['@type']).toBe('BreadcrumbList');
    expect(jsonLd.itemListElement.map((i) => i.name)).toEqual([
      'koopa.dev',
      'projects',
      'Test Project',
    ]);
  });
});
