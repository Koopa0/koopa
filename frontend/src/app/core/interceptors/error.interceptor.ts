import {
  HttpInterceptorFn,
  HttpErrorResponse,
  HttpRequest,
  HttpHandlerFn,
} from '@angular/common/http';
import { inject, Injectable, signal } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, switchMap, throwError } from 'rxjs';
import { AuthService } from '../services/auth.service';

/**
 * Request-scoped refresh state to avoid SSR state leaks.
 * Module-level variables are shared across all SSR requests,
 * but providedIn:'root' services are scoped per injector (per request in SSR).
 */
@Injectable({ providedIn: 'root' })
export class RefreshStateService {
  private readonly _isRefreshing = signal(false);
  readonly isRefreshing = this._isRefreshing.asReadonly();

  setRefreshing(value: boolean): void {
    this._isRefreshing.set(value);
  }
}

export const errorInterceptor: HttpInterceptorFn = (req, next) => {
  const router = inject(Router);
  const authService = inject(AuthService);
  const refreshState = inject(RefreshStateService);

  return next(req).pipe(
    catchError((error: HttpErrorResponse) => {
      if (error.status === 401 && !isRefreshRequest(req)) {
        return handle401(req, next, authService, router, refreshState);
      }

      if (error.status === 403) {
        router.navigate(['/login'], {
          queryParams: { error: 'unauthorized' },
        });
      }

      if (error.status === 429) {
        return throwError(() => new HttpErrorResponse({
          status: 429,
          statusText: '請求過於頻繁，請稍後再試',
          url: error.url ?? undefined,
        }));
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
  refreshState: RefreshStateService,
) {
  if (refreshState.isRefreshing()) {
    return logoutAndRedirect(authService, router);
  }

  refreshState.setRefreshing(true);

  return authService.refreshToken().pipe(
    switchMap(() => {
      refreshState.setRefreshing(false);
      const token = authService.accessToken();
      const retryReq = token
        ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
        : req;
      return next(retryReq);
    }),
    catchError((refreshError) => {
      refreshState.setRefreshing(false);
      authService.logout();
      router.navigate(['/login'], {
        queryParams: { returnUrl: sanitizeReturnUrl(router.url) },
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
    queryParams: { returnUrl: sanitizeReturnUrl(router.url) },
  });
  return throwError(() => new Error('Session expired'));
}

/** Validate return URL to prevent open redirect attacks */
function sanitizeReturnUrl(url: string): string {
  if (!url || !url.startsWith('/') || url.startsWith('//') || url.includes('://')) {
    return '/admin';
  }
  return url;
}
