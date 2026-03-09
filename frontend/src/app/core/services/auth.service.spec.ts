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
    user_id: 'user-001',
    email: 'koopa@example.com',
    role: 'admin',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
  });

  const fakeRefreshToken = 'refresh-token-abc';

  const loginResponse = {
    access_token: fakeAccessToken,
    refresh_token: fakeRefreshToken,
  };

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

  describe('login', () => {
    it('should login with email and password and update auth state', () => {
      let loggedIn = false;
      service.login({ email: 'koopa@example.com', password: 'pass123' }).subscribe(() => {
        loggedIn = true;
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/auth/login'));
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({
        email: 'koopa@example.com',
        password: 'pass123',
      });
      req.flush({ data: loginResponse });

      expect(loggedIn).toBe(true);
      expect(service.isAuthenticated()).toBe(true);
      expect(service.currentUser()?.email).toBe('koopa@example.com');
      expect(service.currentUser()?.id).toBe('user-001');
      expect(service.currentUser()?.role).toBe('admin');
      expect(service.isAdmin()).toBe(true);
      expect(service.accessToken()).toBe(fakeAccessToken);
    });

    it('should store tokens in auth state', () => {
      service.login({ email: 'koopa@example.com', password: 'pass123' }).subscribe();

      const req = httpMock.expectOne((r) => r.url.includes('/api/auth/login'));
      req.flush({ data: loginResponse });

      const state = service.authState();
      expect(state.tokens?.accessToken).toBe(fakeAccessToken);
      expect(state.tokens?.refreshToken).toBe(fakeRefreshToken);
    });

    it('should return error for invalid credentials (401)', () => {
      let errorCaught = false;
      let errorMessage = '';
      service.login({ email: 'wrong@example.com', password: 'wrong' }).subscribe({
        error: (err) => {
          errorCaught = true;
          errorMessage = err.message;
        },
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/auth/login'));
      req.flush('Unauthorized', { status: 401, statusText: 'Unauthorized' });

      expect(errorCaught).toBe(true);
      expect(errorMessage).toBe('Invalid email or password');
      expect(service.isAuthenticated()).toBe(false);
    });

    it('should return generic error for non-401 failures', () => {
      let errorMessage = '';
      service.login({ email: 'koopa@example.com', password: 'pass123' }).subscribe({
        error: (err) => {
          errorMessage = err.message;
        },
      });

      const req = httpMock.expectOne((r) => r.url.includes('/api/auth/login'));
      req.flush('Server Error', { status: 500, statusText: 'Internal Server Error' });

      expect(errorMessage).toBe('Login failed. Please try again later.');
    });
  });

  describe('logout', () => {
    it('should clear auth state on logout', () => {
      // First login
      service.login({ email: 'koopa@example.com', password: 'pass123' }).subscribe();
      const req = httpMock.expectOne((r) => r.url.includes('/api/auth/login'));
      req.flush({ data: loginResponse });
      expect(service.isAuthenticated()).toBe(true);

      // Then logout
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
      // Login first
      service.login({ email: 'koopa@example.com', password: 'pass123' }).subscribe();
      const loginReq = httpMock.expectOne((r) => r.url.includes('/api/auth/login'));
      loginReq.flush({ data: loginResponse });

      // Then refresh
      const newAccessToken = createFakeJwt({
        user_id: 'user-001',
        email: 'koopa@example.com',
        role: 'admin',
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
      // Login first
      service.login({ email: 'koopa@example.com', password: 'pass123' }).subscribe();
      const loginReq = httpMock.expectOne((r) => r.url.includes('/api/auth/login'));
      loginReq.flush({ data: loginResponse });
      expect(service.isAuthenticated()).toBe(true);

      // Refresh fails
      service.refreshToken().subscribe({
        error: () => {
          // expected
        },
      });

      const refreshReq = httpMock.expectOne((r) => r.url.includes('/api/auth/refresh'));
      refreshReq.flush('Unauthorized', { status: 401, statusText: 'Unauthorized' });

      expect(service.isAuthenticated()).toBe(false);
      expect(service.currentUser()).toBeNull();
    });
  });
});
