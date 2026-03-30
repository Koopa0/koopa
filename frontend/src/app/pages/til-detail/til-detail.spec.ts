import { ComponentFixture, TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { TilDetailComponent } from './til-detail';

function createMockContent(overrides: Record<string, unknown> = {}) {
  return {
    id: '1',
    slug: 'test-til',
    title: 'Test TIL',
    body: '# Test TIL\n\nLearned something today.',
    excerpt: 'A test TIL entry',
    type: 'til',
    status: 'published',
    tags: ['Go'],
    topics: [],
    cover_image: null,
    source: null,
    source_type: null,
    series_id: null,
    series_order: null,
    review_level: 'auto',
    visibility: 'public',
    ai_metadata: null,
    reading_time: 1,
    published_at: '2026-01-01T00:00:00Z',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

describe('TilDetailComponent', () => {
  let component: TilDetailComponent;
  let fixture: ComponentFixture<TilDetailComponent>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TilDetailComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        provideNoopAnimations(),
      ],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(TilDetailComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should create', () => {
    fixture.componentRef.setInput('slug', 'test-til');
    fixture.detectChanges();
    const req = httpMock.expectOne((r) => r.url.includes('/api/contents/test-til'));
    req.flush({ data: createMockContent() });
    expect(component).toBeTruthy();
  });

  it('should load TIL entry when slug provided', () => {
    fixture.componentRef.setInput('slug', 'test-til');
    fixture.detectChanges();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/test-til'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: createMockContent() });

    expect(component['til']()).toBeTruthy();
    expect(component['til']()!.title).toBe('Test TIL');
    expect(component['isLoading']()).toBe(false);
  });

  it('should handle HTTP error', () => {
    fixture.componentRef.setInput('slug', 'bad-slug');
    fixture.detectChanges();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/bad-slug'),
    );
    req.flush('Not Found', { status: 404, statusText: 'Not Found' });

    expect(component['error']()).toBe('Failed to load TIL entry');
    expect(component['isLoading']()).toBe(false);
  });
});
