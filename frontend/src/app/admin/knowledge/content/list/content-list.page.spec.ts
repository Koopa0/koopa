import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { ContentListPageComponent } from './content-list.page';
import { AdminTopbarService } from '../../../admin-layout/admin-topbar.service';
import type {
  ApiContent,
  ApiListResponse,
} from '../../../../core/models';

// Mocks only the real HTTP boundary (GET /api/admin/knowledge/content). The
// rows() guard reads the envelope via hasValue() ? value().data : [] — a
// failed read must fall back to [] and surface the error banner rather than
// throw a ResourceValueError.
const LIST_URL = '/api/admin/knowledge/content';

function content(overrides: Partial<ApiContent> = {}): ApiContent {
  return {
    id: 'c0000000-0000-0000-0000-000000000001',
    slug: 'value-semantics-in-go',
    title: 'Value semantics in Go',
    body: '',
    excerpt: '',
    type: 'article',
    status: 'draft',
    tags: [],
    topics: [],
    cover_image: null,
    series_id: null,
    series_order: null,
    is_public: false,
    ai_metadata: null,
    reading_time_min: 5,
    published_at: null,
    created_at: '2026-06-01T10:00:00Z',
    updated_at: '2026-06-10T10:00:00Z',
    ...overrides,
  };
}

function envelope(rows: ApiContent[]): ApiListResponse<ApiContent> {
  return {
    data: rows,
    meta: { total: rows.length, page: 1, per_page: 100, total_pages: 1 },
  };
}

describe('ContentListPageComponent', () => {
  let fixture: ComponentFixture<ContentListPageComponent>;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ContentListPageComponent],
      providers: [
        provideRouter([]),
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        {
          provide: AdminTopbarService,
          useValue: { set: () => undefined, reset: () => undefined },
        },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
    TestBed.resetTestingModule();
  });

  function el(): HTMLElement {
    return fixture.nativeElement as HTMLElement;
  }

  function testid(id: string): HTMLElement | null {
    return el().querySelector(`[data-testid="${id}"]`);
  }

  async function settle(): Promise<void> {
    await new Promise<void>((r) => setTimeout(r, 0));
    fixture.detectChanges();
  }

  it('should render a row per content item from the list envelope', async () => {
    fixture = TestBed.createComponent(ContentListPageComponent);
    fixture.detectChanges();
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(LIST_URL))
      .flush(envelope([content({ title: 'Value semantics in Go' })]));
    await settle();

    expect(testid('content-list-row-0')?.textContent).toContain(
      'Value semantics in Go',
    );
    expect(testid('content-count')?.textContent).toContain('1');
  });

  it('should surface the error banner without throwing when the list read fails', async () => {
    fixture = TestBed.createComponent(ContentListPageComponent);
    fixture.detectChanges();
    // Fail the read with a 500. rows() must fall back to [] via the hasValue()
    // guard rather than throw a ResourceValueError, and the error banner must
    // render.
    httpMock
      .expectOne((r) => r.method === 'GET' && r.url.endsWith(LIST_URL))
      .flush(
        { error: { code: 'INTERNAL', message: 'boom' } },
        { status: 500, statusText: 'Server Error' },
      );
    await settle();

    expect(testid('content-list-error')).not.toBeNull();
    expect(testid('content-list-row-0')).toBeNull();
  });
});
