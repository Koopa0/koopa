import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { CanActivateFn, CanActivateChildFn } from '@angular/router';
import { AuthService } from '../services/auth.service';

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authService.isAuthenticated()) {
    return true;
  }

  router.navigate(['/login'], {
    queryParams: { returnUrl: state.url },
  });
  return false;
};

/** Alias — backend validates email allowlist via OAuth, so authenticated = admin */
export const adminGuard = authGuard;

export const authChildGuard: CanActivateChildFn = (route, state) => {
  return authGuard(route, state);
};

export const adminChildGuard = authChildGuard;
