import { TestBed } from '@angular/core/testing';
import { Router, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { signal } from '@angular/core';
import { AuthService } from '../services/auth.service';
import {
  authGuard,
  adminGuard,
  authChildGuard,
  adminChildGuard,
} from './auth.guard';

describe('Auth Guards', () => {
  let mockRouter: { navigate: ReturnType<typeof vi.fn> };
  let mockIsAuthenticated: ReturnType<typeof signal<boolean>>;
  let mockIsAdmin: ReturnType<typeof signal<boolean>>;
  let route: ActivatedRouteSnapshot;
  let state: RouterStateSnapshot;

  beforeEach(() => {
    mockIsAuthenticated = signal(false);
    mockIsAdmin = signal(false);
    mockRouter = { navigate: vi.fn() };

    TestBed.configureTestingModule({
      providers: [
        {
          provide: AuthService,
          useValue: {
            isAuthenticated: mockIsAuthenticated,
            isAdmin: mockIsAdmin,
          },
        },
        { provide: Router, useValue: mockRouter },
      ],
    });

    route = {} as ActivatedRouteSnapshot;
    state = { url: '/admin/dashboard' } as RouterStateSnapshot;
  });

  describe('authGuard', () => {
    it('should allow access when authenticated', () => {
      mockIsAuthenticated.set(true);

      const result = TestBed.runInInjectionContext(() =>
        authGuard(route, state),
      );

      expect(result).toBe(true);
    });

    it('should redirect to login when not authenticated', () => {
      mockIsAuthenticated.set(false);

      const result = TestBed.runInInjectionContext(() =>
        authGuard(route, state),
      );

      expect(result).toBe(false);
      expect(mockRouter.navigate).toHaveBeenCalledWith(['/login'], {
        queryParams: { returnUrl: '/admin/dashboard' },
      });
    });
  });

  describe('adminGuard', () => {
    it('should allow access when authenticated and admin', () => {
      mockIsAuthenticated.set(true);
      mockIsAdmin.set(true);

      const result = TestBed.runInInjectionContext(() =>
        adminGuard(route, state),
      );

      expect(result).toBe(true);
    });

    it('should redirect to login when not authenticated', () => {
      mockIsAuthenticated.set(false);
      mockIsAdmin.set(false);

      const result = TestBed.runInInjectionContext(() =>
        adminGuard(route, state),
      );

      expect(result).toBe(false);
      expect(mockRouter.navigate).toHaveBeenCalledWith(['/login'], {
        queryParams: { returnUrl: '/admin/dashboard' },
      });
    });

    it('should redirect to home when authenticated but not admin', () => {
      mockIsAuthenticated.set(true);
      mockIsAdmin.set(false);

      const result = TestBed.runInInjectionContext(() =>
        adminGuard(route, state),
      );

      expect(result).toBe(false);
      expect(mockRouter.navigate).toHaveBeenCalledWith(['/'], {
        queryParams: { error: 'unauthorized' },
      });
    });
  });

  describe('authChildGuard', () => {
    it('should delegate to authGuard', () => {
      mockIsAuthenticated.set(true);

      const result = TestBed.runInInjectionContext(() =>
        authChildGuard(route, state),
      );

      expect(result).toBe(true);
    });
  });

  describe('adminChildGuard', () => {
    it('should delegate to adminGuard', () => {
      mockIsAuthenticated.set(true);
      mockIsAdmin.set(true);

      const result = TestBed.runInInjectionContext(() =>
        adminChildGuard(route, state),
      );

      expect(result).toBe(true);
    });
  });
});
