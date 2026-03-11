import { TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideHttpClient } from '@angular/common/http';
import { ReviewService } from './review.service';

describe('ReviewService', () => {
  let service: ReviewService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ReviewService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should fetch reviews', () => {
    service.getReviews().subscribe((res) => {
      expect(res.data).toHaveLength(0);
    });

    const req = httpMock.expectOne((r) => r.url.includes('/api/admin/review'));
    expect(req.request.method).toBe('GET');
    req.flush({ data: [] });
  });

  it('should approve review', () => {
    service.approveReview('123').subscribe();

    const req = httpMock.expectOne((r) => r.url.includes('/api/admin/review/123/approve'));
    expect(req.request.method).toBe('POST');
    req.flush(null);
  });

  it('should reject review with notes', () => {
    service.rejectReview('123', 'needs more detail').subscribe();

    const req = httpMock.expectOne((r) => r.url.includes('/api/admin/review/123/reject'));
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ notes: 'needs more detail' });
    req.flush(null);
  });
});
