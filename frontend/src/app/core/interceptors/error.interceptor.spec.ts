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
import { Router } from '@angular/router';
import { signal } from '@angular/core';
import { of, throwError } from 'rxjs';
import { errorInterceptor, RefreshStateService } from './error.interceptor';
import { AuthService } from '../services/auth.service';

describe('errorInterceptor', () => {
  let httpClient: HttpClient;
  let httpMock: HttpTestingController;
  let mockRouter: { navigate: ReturnType<typeof vi.fn>; url: string };
  let mockAuthService: {
    refreshToken: ReturnType<typeof vi.fn>;
    logout: ReturnType<typeof vi.fn>;
    accessToken: ReturnType<typeof signal<string | null>>;
  };
  let refreshState: RefreshStateService;

  beforeEach(() => {
    mockRouter = { navigate: vi.fn(), url: '/admin/dashboard' };
    mockAuthService = {
      refreshToken: vi.fn(),
      logout: vi.fn(),
      accessToken: signal<string | null>(null),
    };

    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([errorInterceptor])),
        provideHttpClientTesting(),
        { provide: Router, useValue: mockRouter },
        { provide: AuthService, useValue: mockAuthService },
        RefreshStateService,
      ],
    });

    httpClient = TestBed.inject(HttpClient);
    httpMock = TestBed.inject(HttpTestingController);
    refreshState = TestBed.inject(RefreshStateService);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should pass through successful responses', () => {
    httpClient.get('/api/test').subscribe((data) => {
      expect(data).toEqual({ ok: true });
    });

    const req = httpMock.expectOne('/api/test');
    req.flush({ ok: true });
  });

  describe('401 handling', () => {
    it('should attempt token refresh on 401 and retry the request', () => {
      mockAuthService.refreshToken.mockReturnValue(of({ access_token: 'new-token', refresh_token: 'new-refresh' }));
      mockAuthService.accessToken = signal<string | null>('new-token');

      httpClient.get('/api/protected').subscribe((data) => {
        expect(data).toEqual({ result: 'ok' });
      });

      const req = httpMock.expectOne('/api/protected');
      req.flush('Unauthorized', { status: 401, statusText: 'Unauthorized' });

      // After refresh, the request should be retried
      const retryReq = httpMock.expectOne('/api/protected');
      expect(retryReq.request.headers.get('Authorization')).toBe('Bearer new-token');
      retryReq.flush({ result: 'ok' });
    });

    it('should logout and redirect to login when refresh fails', () => {
      mockAuthService.refreshToken.mockReturnValue(
        throwError(() => new Error('Refresh failed')),
      );

      httpClient.get('/api/protected').subscribe({
        error: () => {
          expect(mockAuthService.logout).toHaveBeenCalled();
          expect(mockRouter.navigate).toHaveBeenCalledWith(['/login'], {
            queryParams: { returnUrl: '/admin/dashboard' },
          });
        },
      });

      const req = httpMock.expectOne('/api/protected');
      req.flush('Unauthorized', { status: 401, statusText: 'Unauthorized' });
    });

    it('should not retry refresh endpoint itself on 401', () => {
      httpClient.get('/api/auth/refresh').subscribe({
        error: (err: { status: number }) => {
          expect(err.status).toBe(401);
        },
      });

      const req = httpMock.expectOne('/api/auth/refresh');
      req.flush('Unauthorized', { status: 401, statusText: 'Unauthorized' });

      // Should not attempt refresh
      expect(mockAuthService.refreshToken).not.toHaveBeenCalled();
    });

    it('should logout immediately when already refreshing', () => {
      refreshState.setRefreshing(true);

      httpClient.get('/api/protected').subscribe({
        error: () => {
          expect(mockAuthService.logout).toHaveBeenCalled();
          expect(mockRouter.navigate).toHaveBeenCalledWith(['/login'], {
            queryParams: { returnUrl: '/admin/dashboard' },
          });
        },
      });

      const req = httpMock.expectOne('/api/protected');
      req.flush('Unauthorized', { status: 401, statusText: 'Unauthorized' });
    });
  });

  describe('403 handling', () => {
    it('should navigate to login with error query param on 403', () => {
      httpClient.get('/api/admin/resource').subscribe({
        error: (err: { status: number }) => {
          expect(err.status).toBe(403);
          expect(mockRouter.navigate).toHaveBeenCalledWith(['/login'], {
            queryParams: { error: 'unauthorized' },
          });
        },
      });

      const req = httpMock.expectOne('/api/admin/resource');
      req.flush('Forbidden', { status: 403, statusText: 'Forbidden' });
    });
  });

  describe('429 handling', () => {
    it('should return custom statusText for rate limited requests', () => {
      httpClient.get('/api/rate-limited').subscribe({
        error: (err: { status: number; statusText: string }) => {
          expect(err.status).toBe(429);
          expect(err.statusText).toBe('請求過於頻繁，請稍後再試');
        },
      });

      const req = httpMock.expectOne('/api/rate-limited');
      req.flush('Too Many Requests', { status: 429, statusText: 'Too Many Requests' });
    });
  });

  describe('other errors', () => {
    it('should propagate 404 error to subscriber', () => {
      httpClient.get('/api/missing').subscribe({
        error: (err: { status: number }) => {
          expect(err.status).toBe(404);
        },
      });

      const req = httpMock.expectOne('/api/missing');
      req.flush('Not Found', { status: 404, statusText: 'Not Found' });
    });

    it('should propagate 500 error to subscriber', () => {
      httpClient.get('/api/broken').subscribe({
        error: (err: { status: number }) => {
          expect(err.status).toBe(500);
        },
      });

      const req = httpMock.expectOne('/api/broken');
      req.flush('Server Error', { status: 500, statusText: 'Internal Server Error' });
    });

    it('should propagate network error (status 0) to subscriber', () => {
      httpClient.get('/api/offline').subscribe({
        error: (err: { status: number }) => {
          expect(err.status).toBe(0);
        },
      });

      const req = httpMock.expectOne('/api/offline');
      req.error(new ProgressEvent('error'), { status: 0, statusText: 'Unknown Error' });
    });
  });

  describe('RefreshStateService', () => {
    it('should track refreshing state', () => {
      expect(refreshState.isRefreshing()).toBe(false);

      refreshState.setRefreshing(true);
      expect(refreshState.isRefreshing()).toBe(true);

      refreshState.setRefreshing(false);
      expect(refreshState.isRefreshing()).toBe(false);
    });
  });
});
