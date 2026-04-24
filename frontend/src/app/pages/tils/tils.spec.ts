import { ComponentFixture, TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { TilsComponent } from './tils';

function createMockTil(overrides: Record<string, unknown> = {}) {
  return {
    id: '1',
    slug: 'test-til',
    title: 'Test TIL',
    body: '# Test',
    excerpt: '',
    type: 'til',
    status: 'published',
    tags: [] as string[],
    topics: [],
    cover_image: null,
    source: null,
    source_type: null,
    series_id: null,
    series_order: null,
    is_public: true,
    ai_metadata: null,
    reading_time_min: 1,
    published_at: '2026-01-01T00:00:00Z',
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

const EMPTY_META = { total: 0, page: 1, per_page: 100, total_pages: 0 };

describe('TilsComponent', () => {
  let component: TilsComponent;
  let fixture: ComponentFixture<TilsComponent>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TilsComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        provideNoopAnimations(),
      ],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(TilsComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should create', () => {
    fixture.detectChanges();
    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/by-type/til'),
    );
    req.flush({ data: [], meta: EMPTY_META });
    expect(component).toBeTruthy();
  });

  it('should load TIL entries on init', () => {
    fixture.detectChanges();
    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/by-type/til'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({
      data: [createMockTil()],
      meta: { total: 1, page: 1, per_page: 100, total_pages: 1 },
    });
    expect(component['tils']().length).toBe(1);
    expect(component['isLoading']()).toBe(false);
  });

  it('should set error on load failure', () => {
    fixture.detectChanges();
    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/by-type/til'),
    );
    req.flush('Server Error', {
      status: 500,
      statusText: 'Internal Server Error',
    });
    expect(component['error']()).toBe('Failed to load TIL entries');
    expect(component['isLoading']()).toBe(false);
  });

  it('should handle empty response', () => {
    fixture.detectChanges();
    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/by-type/til'),
    );
    req.flush({ data: [], meta: EMPTY_META });
    expect(component['tils']().length).toBe(0);
    expect(component['isLoading']()).toBe(false);
  });

  it('should filter tils by selected tag', () => {
    fixture.detectChanges();
    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/by-type/til'),
    );
    req.flush({
      data: [
        createMockTil({ id: '1', slug: 'til-go', tags: ['Go'] }),
        createMockTil({ id: '2', slug: 'til-angular', tags: ['Angular'] }),
        createMockTil({
          id: '3',
          slug: 'til-go2',
          tags: ['Go', 'Concurrency'],
        }),
      ],
      meta: { total: 3, page: 1, per_page: 100, total_pages: 1 },
    });

    component['selectTag']('Go');
    expect(component['filteredTils']().length).toBe(2);

    component['selectTag'](null);
    expect(component['filteredTils']().length).toBe(3);
  });

  it('should compute allTags as sorted unique list', () => {
    fixture.detectChanges();
    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/by-type/til'),
    );
    req.flush({
      data: [
        createMockTil({ id: '1', tags: ['Go', 'Angular'] }),
        createMockTil({ id: '2', tags: ['Angular', 'Rust'] }),
      ],
      meta: { total: 2, page: 1, per_page: 100, total_pages: 1 },
    });

    const tags = component['allTags']();
    expect(tags).toEqual(['Angular', 'Go', 'Rust']);
  });
});
