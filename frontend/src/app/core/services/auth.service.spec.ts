import { TestBed, fakeAsync, tick } from '@angular/core/testing';
import { AuthService } from './auth.service';

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(AuthService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should start as unauthenticated', () => {
    expect(service.isAuthenticated()).toBe(false);
    expect(service.currentUser()).toBeNull();
    expect(service.isAdmin()).toBe(false);
  });

  it('should login with correct credentials', fakeAsync(() => {
    let loggedIn = false;
    service.login({ username: 'koopa', password: 'koopa123' }).subscribe(() => {
      loggedIn = true;
    });
    tick(1000);

    expect(loggedIn).toBe(true);
    expect(service.isAuthenticated()).toBe(true);
    expect(service.currentUser()?.username).toBe('koopa');
    expect(service.isAdmin()).toBe(true);
  }));

  it('should reject invalid credentials', fakeAsync(() => {
    let errorCaught = false;
    service.login({ username: 'wrong', password: 'wrong' }).subscribe({
      error: () => {
        errorCaught = true;
      },
    });
    tick(1000);

    expect(errorCaught).toBe(true);
    expect(service.isAuthenticated()).toBe(false);
  }));

  it('should keep token only in memory after login', fakeAsync(() => {
    service.login({ username: 'koopa', password: 'koopa123' }).subscribe();
    tick(1000);

    expect(service.authState().token).not.toBeNull();
    expect(localStorage.getItem('koopa_blog_token')).toBeNull();
    expect(localStorage.getItem('koopa_blog_user')).toBeNull();
  }));

  it('should clear auth state on logout', fakeAsync(() => {
    service.login({ username: 'koopa', password: 'koopa123' }).subscribe();
    tick(1000);
    expect(service.isAuthenticated()).toBe(true);

    service.logout();
    expect(service.isAuthenticated()).toBe(false);
    expect(service.currentUser()).toBeNull();
    expect(service.authState().token).toBeNull();
  }));

  it('should return error when refreshing without token', fakeAsync(() => {
    let errorCaught = false;
    service.refreshToken().subscribe({
      error: (err) => {
        errorCaught = true;
        expect(err.message).toContain('No token');
      },
    });
    tick(200);

    expect(errorCaught).toBe(true);
  }));

  it('should refresh token when authenticated', fakeAsync(() => {
    service.login({ username: 'koopa', password: 'koopa123' }).subscribe();
    tick(1000);

    let refreshed = false;
    service.refreshToken().subscribe(() => {
      refreshed = true;
    });
    tick(200);

    expect(refreshed).toBe(true);
    expect(service.isAuthenticated()).toBe(true);
    expect(service.authState().token).not.toBeNull();
    expect(service.currentUser()?.username).toBe('koopa');
  }));
});
