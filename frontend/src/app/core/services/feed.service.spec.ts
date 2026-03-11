import { TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { FeedService } from './feed.service';

describe('FeedService', () => {
  let service: FeedService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(FeedService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should fetch feeds', () => {
    service.getFeeds().subscribe((res) => {
      expect(res.data).toHaveLength(1);
    });

    const req = httpMock.expectOne((r) => r.url.includes('/api/admin/feeds'));
    expect(req.request.method).toBe('GET');
    req.flush({ data: [{ id: '1', name: 'Test Feed' }] });
  });

  it('should create feed', () => {
    service
      .createFeed({ url: 'https://example.com/feed', name: 'Test', schedule: 'daily' })
      .subscribe();

    const req = httpMock.expectOne((r) => r.url.includes('/api/admin/feeds'));
    expect(req.request.method).toBe('POST');
    req.flush({ data: { id: '1', name: 'Test' } });
  });

  it('should delete feed', () => {
    service.deleteFeed('123').subscribe();

    const req = httpMock.expectOne((r) => r.url.includes('/api/admin/feeds/123'));
    expect(req.request.method).toBe('DELETE');
    req.flush(null);
  });

  it('should fetch a specific feed', () => {
    service.fetchFeed('123').subscribe();

    const req = httpMock.expectOne((r) => r.url.includes('/api/admin/feeds/123/fetch'));
    expect(req.request.method).toBe('POST');
    req.flush({ data: { new_items: 5 } });
  });
});
