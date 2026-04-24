import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { AuthService } from './auth.service';

/** Helper: create a fake JWT with given payload */
function createFakeJwt(payload: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify(payload));
  const signature = 'fake-signature';
  return `${header}.${body}.${signature}`;
}

describe('AuthService', () => {
  let service: AuthService;
  let httpMock: HttpTestingController;

  const fakeAccessToken = createFakeJwt({
    sub: 'koopa@example.com',
    email: 'koopa@example.com',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
  });

  const fakeRefreshToken = 'refresh-token-abc';

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(AuthService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should start as unauthenticated', () => {
    expect(service.isAuthenticated()).toBe(false);
    expect(service.currentUser()).toBeNull();
    expect(service.isAdmin()).toBe(false);
    expect(service.accessToken()).toBeNull();
  });

  describe('handleOAuthCallback', () => {
    it('should set auth state from OAuth tokens', () => {
      service.handleOAuthCallback(fakeAccessToken, fakeRefreshToken);

      expect(service.isAuthenticated()).toBe(true);
      expect(service.currentUser()?.email).toBe('koopa@example.com');
      expect(service.isAdmin()).toBe(true);
      expect(service.accessToken()).toBe(fakeAccessToken);
    });

    it('should store both tokens in auth state', () => {
      service.handleOAuthCallback(fakeAccessToken, fakeRefreshToken);

      const state = service.authState();
      expect(state.tokens?.accessToken).toBe(fakeAccessToken);
      expect(state.tokens?.refreshToken).toBe(fakeRefreshToken);
    });
  });

  describe('logout', () => {
    it('should clear auth state on logout', () => {
      service.handleOAuthCallback(fakeAccessToken, fakeRefreshToken);
      expect(service.isAuthenticated()).toBe(true);

      service.logout();
      expect(service.isAuthenticated()).toBe(false);
      expect(service.currentUser()).toBeNull();
      expect(service.authState().tokens).toBeNull();
      expect(service.accessToken()).toBeNull();
    });
  });

  describe('refreshToken', () => {
    it('should return error when no refresh token exists', () => {
      let errorCaught = false;
      service.refreshToken().subscribe({
        error: (err) => {
          errorCaught = true;
          expect(err.message).toContain('No refresh token');
        },
      });

      expect(errorCaught).toBe(true);
    });

    it('should refresh token when authenticated', () => {
      service.handleOAuthCallback(fakeAccessToken, fakeRefreshToken);

      const newAccessToken = createFakeJwt({
        sub: 'koopa@example.com',
        email: 'koopa@example.com',
        exp: Math.floor(Date.now() / 1000) + 7200,
        iat: Math.floor(Date.now() / 1000),
      });

      let refreshed = false;
      service.refreshToken().subscribe(() => {
        refreshed = true;
      });

      const refreshReq = httpMock.expectOne((r) => r.url.includes('/api/auth/refresh'));
      expect(refreshReq.request.method).toBe('POST');
      expect(refreshReq.request.body).toEqual({ refresh_token: fakeRefreshToken });
      refreshReq.flush({
        data: { access_token: newAccessToken, refresh_token: 'new-refresh-token' },
      });

      expect(refreshed).toBe(true);
      expect(service.isAuthenticated()).toBe(true);
      expect(service.accessToken()).toBe(newAccessToken);
      expect(service.authState().tokens?.refreshToken).toBe('new-refresh-token');
    });

    it('should logout on refresh failure', () => {
      service.handleOAuthCallback(fakeAccessToken, fakeRefreshToken);
      expect(service.isAuthenticated()).toBe(true);

      service.refreshToken().subscribe({
        error: () => {
          /* expected */
        },
      });

      const refreshReq = httpMock.expectOne((r) => r.url.includes('/api/auth/refresh'));
      refreshReq.flush('Unauthorized', { status: 401, statusText: 'Unauthorized' });

      expect(service.isAuthenticated()).toBe(false);
      expect(service.currentUser()).toBeNull();
    });
  });

  describe('isAdmin', () => {
    it('should return true when authenticated (backend validates allowlist)', () => {
      service.handleOAuthCallback(fakeAccessToken, fakeRefreshToken);
      expect(service.isAdmin()).toBe(true);
    });

    it('should return false when not authenticated', () => {
      expect(service.isAdmin()).toBe(false);
    });
  });
});
