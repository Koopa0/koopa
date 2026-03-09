import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { AuthService } from '../services/auth.service';
import {
  authGuard,
  adminGuard,
  authChildGuard,
  adminChildGuard,
} from './auth.guard';

describe('Auth Guards', () => {
  let authService: jasmine.SpyObj<AuthService>;
  let router: jasmine.SpyObj<Router>;
  let route: ActivatedRouteSnapshot;
  let state: RouterStateSnapshot;

  beforeEach(() => {
    authService = jasmine.createSpyObj('AuthService', [
      'isAuthenticated',
      'isAdmin',
    ]);
    router = jasmine.createSpyObj('Router', ['navigate']);

    TestBed.configureTestingModule({
      providers: [
        { provide: AuthService, useValue: authService },
        { provide: Router, useValue: router },
      ],
    });

    route = {} as ActivatedRouteSnapshot;
    state = { url: '/admin/dashboard' } as RouterStateSnapshot;
  });

  describe('authGuard', () => {
    it('should allow access when authenticated', () => {
      authService.isAuthenticated.and.returnValue(true);

      const result = TestBed.runInInjectionContext(() =>
        authGuard(route, state),
      );

      expect(result).toBe(true);
    });

    it('should redirect to login when not authenticated', () => {
      authService.isAuthenticated.and.returnValue(false);

      const result = TestBed.runInInjectionContext(() =>
        authGuard(route, state),
      );

      expect(result).toBe(false);
      expect(router.navigate).toHaveBeenCalledWith(['/login'], {
        queryParams: { returnUrl: '/admin/dashboard' },
      });
    });
  });

  describe('adminGuard', () => {
    it('should allow access when authenticated and admin', () => {
      authService.isAuthenticated.and.returnValue(true);
      authService.isAdmin.and.returnValue(true);

      const result = TestBed.runInInjectionContext(() =>
        adminGuard(route, state),
      );

      expect(result).toBe(true);
    });

    it('should redirect to login when not authenticated', () => {
      authService.isAuthenticated.and.returnValue(false);
      authService.isAdmin.and.returnValue(false);

      const result = TestBed.runInInjectionContext(() =>
        adminGuard(route, state),
      );

      expect(result).toBe(false);
      expect(router.navigate).toHaveBeenCalledWith(['/login'], {
        queryParams: { returnUrl: '/admin/dashboard' },
      });
    });

    it('should redirect to home when authenticated but not admin', () => {
      authService.isAuthenticated.and.returnValue(true);
      authService.isAdmin.and.returnValue(false);

      const result = TestBed.runInInjectionContext(() =>
        adminGuard(route, state),
      );

      expect(result).toBe(false);
      expect(router.navigate).toHaveBeenCalledWith(['/'], {
        queryParams: { error: 'unauthorized' },
      });
    });
  });

  describe('authChildGuard', () => {
    it('should delegate to authGuard', () => {
      authService.isAuthenticated.and.returnValue(true);

      const result = TestBed.runInInjectionContext(() =>
        authChildGuard(route, state),
      );

      expect(result).toBe(true);
    });
  });

  describe('adminChildGuard', () => {
    it('should delegate to adminGuard', () => {
      authService.isAuthenticated.and.returnValue(true);
      authService.isAdmin.and.returnValue(true);

      const result = TestBed.runInInjectionContext(() =>
        adminChildGuard(route, state),
      );

      expect(result).toBe(true);
    });
  });
});
