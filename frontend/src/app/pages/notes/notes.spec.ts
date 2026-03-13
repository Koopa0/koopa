import { ComponentFixture, TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideRouter } from '@angular/router';
import { provideNoopAnimations } from '@angular/platform-browser/animations';
import { NotesComponent } from './notes';

describe('NotesComponent', () => {
  let component: NotesComponent;
  let fixture: ComponentFixture<NotesComponent>;
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [NotesComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        provideNoopAnimations(),
      ],
    }).compileComponents();

    httpMock = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(NotesComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should create', () => {
    fixture.detectChanges();
    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/by-type/note'),
    );
    req.flush({
      data: [],
      meta: { total: 0, page: 1, per_page: 100, total_pages: 0 },
    });
    expect(component).toBeTruthy();
  });

  it('should load notes on init', () => {
    fixture.detectChanges();
    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/by-type/note'),
    );
    expect(req.request.method).toBe('GET');
    req.flush({
      data: [
        {
          id: '1',
          slug: 'test-note',
          title: 'Test Note',
          body: '# Test',
          excerpt: '',
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
          ai_metadata: null,
          reading_time: 2,
          published_at: '2026-01-01T00:00:00Z',
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
        },
      ],
      meta: { total: 1, page: 1, per_page: 100, total_pages: 1 },
    });
    expect(component['notes']().length).toBe(1);
    expect(component['isLoading']()).toBe(false);
  });

  it('should set error on load failure', () => {
    fixture.detectChanges();
    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/by-type/note'),
    );
    req.flush('Server Error', {
      status: 500,
      statusText: 'Internal Server Error',
    });
    expect(component['error']()).toBe('Failed to load notes');
    expect(component['isLoading']()).toBe(false);
  });

  it('should handle empty response', () => {
    fixture.detectChanges();
    const req = httpMock.expectOne((r) =>
      r.url.includes('/api/contents/by-type/note'),
    );
    req.flush({
      data: [],
      meta: { total: 0, page: 1, per_page: 100, total_pages: 0 },
    });
    expect(component['notes']().length).toBe(0);
    expect(component['isLoading']()).toBe(false);
  });
});
