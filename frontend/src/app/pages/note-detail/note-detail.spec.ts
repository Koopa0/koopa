import { ComponentFixture, TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { NoteDetailComponent } from './note-detail';

function createMockContent(overrides: Record<string, unknown> = {}) {
  return {
    id: '1',
    slug: 'test-note',
    title: 'Test Note',
    body: '# Test Note\n\nSome content here.',
    excerpt: 'A test note',
    type: 'note',
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
    reading_time_min: 2,
    published_at: '2026-01-01T00:00:00Z',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

describe('NoteDetailComponent', () => {
  let component: NoteDetailComponent;
  let fixture: ComponentFixture<NoteDetailComponent>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [NoteDetailComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        provideNoopAnimations(),
      ],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(NoteDetailComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should create', () => {
    fixture.componentRef.setInput('slug', 'test-note');
    fixture.detectChanges();
    const req = httpMock.expectOne((r) => r.url.includes('/api/contents/test-note'));
    req.flush({ data: createMockContent() });
    expect(component).toBeTruthy();
  });

  it('should load note when slug provided', () => {
    fixture.componentRef.setInput('slug', 'test-note');
    fixture.detectChanges();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/test-note'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({ data: createMockContent() });

    expect(component['note']()).toBeTruthy();
    expect(component['note']()!.title).toBe('Test Note');
    expect(component['isLoading']()).toBe(false);
  });

  it('should handle HTTP error', () => {
    fixture.componentRef.setInput('slug', 'bad-slug');
    fixture.detectChanges();

    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/bad-slug'),
    );
    req.flush('Not Found', { status: 404, statusText: 'Not Found' });

    expect(component['error']()).toBe('Failed to load note');
    expect(component['isLoading']()).toBe(false);
  });
});
