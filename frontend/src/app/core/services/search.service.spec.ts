import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { SearchService } from './search.service';

describe('SearchService', () => {
  let service: SearchService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting()],
    });
    service = TestBed.inject(SearchService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should call the admin endpoint and unwrap results when adminSearch is called', () => {
    let results: { type: string; title: string }[] | undefined;
    service.adminSearch('pgvector', 10).subscribe((r) => (results = r));

    const req = httpMock.expectOne((r) =>
      r.url.endsWith('/api/admin/search'),
    );
    expect(req.request.params.get('q')).toBe('pgvector');
    expect(req.request.params.get('limit')).toBe('10');
    req.flush({
      data: {
        results: [
          {
            type: 'content',
            id: 'c1',
            slug: 'pgvector-indexing',
            title: 'pgvector indexing',
            excerpt: 'HNSW vs IVFFlat',
            score: 0.9,
          },
        ],
      },
    });

    expect(results?.length).toBe(1);
    expect(results?.[0].type).toBe('content');
  });

  it('should return an empty array when adminSearch results are missing', () => {
    let results: unknown[] | undefined;
    service.adminSearch('nothing').subscribe((r) => (results = r));

    httpMock
      .expectOne((r) => r.url.endsWith('/api/admin/search'))
      .flush({ data: {} });

    expect(results).toEqual([]);
  });

});
