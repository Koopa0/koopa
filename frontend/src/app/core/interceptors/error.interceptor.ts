import {
  HttpInterceptorFn,
  HttpErrorResponse,
  HttpRequest,
  HttpHandlerFn,
} from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, switchMap, throwError } from 'rxjs';
import { AuthService } from '../services/auth.service';

/** Track whether a token refresh is already in progress to avoid loops */
let isRefreshing = false;

export const errorInterceptor: HttpInterceptorFn = (req, next) => {
  const router = inject(Router);
  const authService = inject(AuthService);

  return next(req).pipe(
    catchError((error: HttpErrorResponse) => {
      if (error.status === 401 && !isRefreshRequest(req)) {
        return handle401(req, next, authService, router);
      }

      if (error.status === 403) {
        router.navigate(['/'], {
          queryParams: { error: 'unauthorized' },
        });
      }

      return throwError(() => error);
    }),
  );
};

function handle401(
  req: HttpRequest<unknown>,
  next: HttpHandlerFn,
  authService: AuthService,
  router: Router,
) {
  if (isRefreshing) {
    return logoutAndRedirect(authService, router);
  }

  isRefreshing = true;

  return authService.refreshToken().pipe(
    switchMap(() => {
      isRefreshing = false;
      const token = authService.accessToken();
      const retryReq = token
        ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
        : req;
      return next(retryReq);
    }),
    catchError((refreshError) => {
      isRefreshing = false;
      authService.logout();
      router.navigate(['/login'], {
        queryParams: { returnUrl: router.url },
      });
      return throwError(() => refreshError);
    }),
  );
}

/** Prevent infinite loop: don't retry refresh endpoint itself */
function isRefreshRequest(req: HttpRequest<unknown>): boolean {
  return req.url.includes('/api/auth/refresh');
}

function logoutAndRedirect(authService: AuthService, router: Router) {
  authService.logout();
  router.navigate(['/login'], {
    queryParams: { returnUrl: router.url },
  });
  return throwError(() => new Error('Session expired'));
}
