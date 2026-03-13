import { ComponentFixture, TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { BuildLogsComponent } from './build-logs';

describe('BuildLogsComponent', () => {
  let component: BuildLogsComponent;
  let fixture: ComponentFixture<BuildLogsComponent>;
  let httpMock: HttpTestingController;

  const EMPTY_META = { total: 0, page: 1, per_page: 20, total_pages: 0 };

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [BuildLogsComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        provideNoopAnimations(),
      ],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(BuildLogsComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should create', () => {
    fixture.detectChanges();
    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/by-type/build-log'),
    );
    req.flush({ data: [], meta: EMPTY_META });
    expect(component).toBeTruthy();
  });

  it('should load build logs on init', () => {
    fixture.detectChanges();
    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/by-type/build-log'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({
      data: [
        {
          id: '1',
          slug: 'test-build-log',
          title: 'Test Build Log',
          body: '# Test',
          excerpt: 'Build log excerpt',
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
          ai_metadata: null,
          reading_time: 5,
          published_at: '2026-01-01T00:00:00Z',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
        },
      ],
      meta: { total: 1, page: 1, per_page: 20, total_pages: 1 },
    });
    expect(component['buildLogs']().length).toBe(1);
    expect(component['isLoading']()).toBe(false);
  });

  it('should set error on load failure', () => {
    fixture.detectChanges();
    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/by-type/build-log'),
    );
    req.flush('Server Error', {
      status: 500,
      statusText: 'Internal Server Error',
    });
    expect(component['error']()).toBe('Failed to load build logs');
    expect(component['isLoading']()).toBe(false);
  });

  it('should handle empty response', () => {
    fixture.detectChanges();
    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/by-type/build-log'),
    );
    req.flush({ data: [], meta: EMPTY_META });
    expect(component['buildLogs']().length).toBe(0);
    expect(component['isLoading']()).toBe(false);
  });
});
