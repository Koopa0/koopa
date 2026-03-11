import { TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { CollectedService } from './collected.service';

describe('CollectedService', () => {
  let service: CollectedService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(CollectedService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should fetch collected items with default params', () => {
    service.getCollected().subscribe((res) => {
      expect(res.data).toHaveLength(0);
    });

    const req = httpMock.expectOne((r) => r.url.includes('/api/admin/collected'));
    expect(req.request.method).toBe('GET');
    req.flush({ data: [], meta: { total: 0, page: 1, per_page: 20, total_pages: 0 } });
  });

  it('should send feedback', () => {
    service.sendFeedback('123', 'up').subscribe();

    const req = httpMock.expectOne((r) => r.url.includes('/api/admin/collected/123/feedback'));
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ feedback: 'up' });
    req.flush(null);
  });

  it('should ignore item', () => {
    service.ignoreItem('123').subscribe();

    const req = httpMock.expectOne((r) => r.url.includes('/api/admin/collected/123/ignore'));
    expect(req.request.method).toBe('POST');
    req.flush(null);
  });
});
