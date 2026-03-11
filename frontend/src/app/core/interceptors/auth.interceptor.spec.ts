import { TestBed } from '@angular/core/testing';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import {
  HttpClient,
  provideHttpClient,
  withInterceptors,
} from '@angular/common/http';
import { signal } from '@angular/core';
import { authInterceptor } from './auth.interceptor';
import { AuthService } from '../services/auth.service';

describe('authInterceptor', () => {
  let httpClient: HttpClient;
  let httpMock: HttpTestingController;
  let mockAccessToken: ReturnType<typeof signal<string | null>>;

  beforeEach(() => {
    mockAccessToken = signal<string | null>(null);

    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
        {
          provide: AuthService,
          useValue: { accessToken: mockAccessToken },
        },
      ],
    });

    httpClient = TestBed.inject(HttpClient);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should attach Authorization header when token exists', () => {
    mockAccessToken.set('my-jwt-token');

    httpClient.get('/api/admin/contents').subscribe();

    const req = httpMock.expectOne('/api/admin/contents');
    expect(req.request.headers.get('Authorization')).toBe('Bearer my-jwt-token');
    req.flush({ data: [] });
  });

  it('should not attach Authorization header when no token', () => {
    mockAccessToken.set(null);

    httpClient.get('/api/contents').subscribe();

    const req = httpMock.expectOne('/api/contents');
    expect(req.request.headers.has('Authorization')).toBe(false);
    req.flush({ data: [] });
  });

  it('should pass through request body unchanged', () => {
    mockAccessToken.set('token');

    const body = { title: 'Test', slug: 'test' };
    httpClient.post('/api/admin/contents', body).subscribe();

    const req = httpMock.expectOne('/api/admin/contents');
    expect(req.request.body).toEqual(body);
    expect(req.request.headers.get('Authorization')).toBe('Bearer token');
    req.flush({ data: {} });
  });

  it('should use current token value for each request', () => {
    mockAccessToken.set('token-1');

    httpClient.get('/api/first').subscribe();
    const req1 = httpMock.expectOne('/api/first');
    expect(req1.request.headers.get('Authorization')).toBe('Bearer token-1');
    req1.flush({});

    mockAccessToken.set('token-2');

    httpClient.get('/api/second').subscribe();
    const req2 = httpMock.expectOne('/api/second');
    expect(req2.request.headers.get('Authorization')).toBe('Bearer token-2');
    req2.flush({});
  });
});
