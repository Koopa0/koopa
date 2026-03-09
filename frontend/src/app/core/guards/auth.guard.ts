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
  
  // 重定向到登入頁面，並保存原本要訪問的 URL
  router.navigate(['/login'], { 
    queryParams: { returnUrl: state.url } 
  });
  return false;
};

export const adminGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);
  
  if (authService.isAuthenticated() && authService.isAdmin()) {
    return true;
  }
  
  if (!authService.isAuthenticated()) {
    router.navigate(['/login'], { 
      queryParams: { returnUrl: state.url } 
    });
  } else {
    // 已登入但不是管理員
    router.navigate(['/'], {
      queryParams: { error: 'unauthorized' }
    });
  }
  
  return false;
};

export const authChildGuard: CanActivateChildFn = (route, state) => {
  return authGuard(route, state);
};

export const adminChildGuard: CanActivateChildFn = (route, state) => {
  return adminGuard(route, state);
};