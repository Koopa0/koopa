import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { PLATFORM_ID } from '@angular/core';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { ProjectsComponent } from './projects';
import type { ApiPortfolioProject } from '../../core/models';

function buildMockListing(
  overrides: Partial<ApiPortfolioProject> = {},
): ApiPortfolioProject {
  return {
    id: 'proj-001',
    slug: 'test-project',
    title: 'Test Project',
    description: 'A test project description',
    status: 'in_progress',
    role: 'Architect & sole engineer',
    tech_stack: ['Go', 'Angular'],
    highlights: ['Highlight one', 'Highlight two'],
    featured: false,
    sort_order: 0,
    updated_at: '2026-01-15T10:00:00Z',
    ...overrides,
  };
}

describe('ProjectsComponent', () => {
  let component: ProjectsComponent;
  let fixture: ComponentFixture<ProjectsComponent>;
  let httpTesting: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ProjectsComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        { provide: PLATFORM_ID, useValue: 'browser' },
        provideNoopAnimations(),
      ],
    }).compileComponents();

    httpTesting = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(ProjectsComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    httpTesting.verify();
  });

  /** Flush effects + microtasks so rxResource issues its request. */
  async function settle(): Promise<void> {
    fixture.detectChanges();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    fixture.detectChanges();
  }

  function flushPortfolio(listings: ApiPortfolioProject[]): void {
    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/portfolio') && r.method === 'GET',
    );
    req.flush({ data: listings });
  }

  it('should create', async () => {
    await settle();
    flushPortfolio([]);
    expect(component).toBeTruthy();
  });

  it('should render the backend-flagged project as the featured card', async () => {
    await settle();
    flushPortfolio([
      buildMockListing({ id: '1', slug: 'fsrs-go', title: 'fsrs-go' }),
      buildMockListing({
        id: '2',
        slug: 'koopa',
        title: 'koopa',
        featured: true,
      }),
    ]);
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    const featured = el.querySelector('[data-testid="featured-project"]');
    expect(featured?.textContent).toContain('koopa');

    const rows = el.querySelectorAll('[data-testid="project-row"]');
    expect(rows.length).toBe(1);
    expect(rows[0].textContent).toContain('fsrs-go');
  });

  it('should render only compact rows when no project is flagged featured', async () => {
    await settle();
    flushPortfolio([
      buildMockListing({ id: '1', slug: 'a', title: 'Project A' }),
      buildMockListing({ id: '2', slug: 'b', title: 'Project B' }),
    ]);
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid="featured-project"]')).toBeNull();
    expect(el.querySelectorAll('[data-testid="project-row"]').length).toBe(2);
  });

  it('should show an error state with retry when the request fails', async () => {
    await settle();
    const req = httpTesting.expectOne(
      (r) => r.url.includes('/api/portfolio') && r.method === 'GET',
    );
    req.flush('Server error', {
      status: 500,
      statusText: 'Internal Server Error',
    });
    await settle();

    const el = fixture.nativeElement as HTMLElement;
    expect(el.textContent).toContain('Failed to load projects');
    expect(component['hasError']()).toBe(true);
  });
});
