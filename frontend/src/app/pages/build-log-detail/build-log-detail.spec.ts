import { ComponentFixture, TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { BuildLogDetailComponent } from './build-log-detail';

function createMockContent(overrides: Record<string, unknown> = {}) {
  return {
    id: '1',
    slug: 'test-build-log',
    title: 'Test Build Log',
    body: '# Test Build Log\n\nBuilding something cool.',
    excerpt: 'A test build log',
    type: 'build-log',
    status: 'published',
    tags: [],
    topics: [],
    cover_image: null,
    source: null,
    source_type: null,
    series_id: null,
    series_order: null,
    review_level: 'auto',
    is_public: true,
    ai_metadata: null,
    reading_time_min: 5,
    published_at: '2026-01-01T00:00:00Z',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

describe('BuildLogDetailComponent', () => {
  let component: BuildLogDetailComponent;
  let fixture: ComponentFixture<BuildLogDetailComponent>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [BuildLogDetailComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        provideNoopAnimations(),
      ],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(BuildLogDetailComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should create', () => {
    fixture.componentRef.setInput('slug', 'test-build-log');
    fixture.detectChanges();
    const req = httpMock.expectOne((r) => r.url.includes('/api/contents/test-build-log'));
    req.flush({ data: createMockContent() });
    expect(component).toBeTruthy();
  });

  it('should load build log when slug provided', () => {
    fixture.componentRef.setInput('slug', 'test-build-log');
    fixture.detectChanges();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/test-build-log'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: createMockContent() });

    expect(component['buildLog']()).toBeTruthy();
    expect(component['buildLog']()!.title).toBe('Test Build Log');
    expect(component['isLoading']()).toBe(false);
  });

  it('should handle HTTP error', () => {
    fixture.componentRef.setInput('slug', 'bad-slug');
    fixture.detectChanges();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/bad-slug'),
    );
    req.flush('Not Found', { status: 404, statusText: 'Not Found' });

    expect(component['error']()).toBe('Failed to load build log');
    expect(component['isLoading']()).toBe(false);
  });
});
