import { Injectable, signal, computed } from '@angular/core';
import { Observable, of, throwError, timer, Subscription } from 'rxjs';
import { tap, catchError, switchMap, take } from 'rxjs/operators';
import { LoginRequest, LoginResponse, User, AuthState } from '../models';

// 開發環境用 mock 憑證，未來接 API 後移除此區塊
const MOCK_CREDENTIALS = {
  username: 'koopa',
  password: 'koopa123',
} as const;

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private refreshSubscription: Subscription | null = null;

  private readonly _authState = signal<AuthState>({
    isAuthenticated: false,
    user: null,
    token: null,
  });

  readonly authState = this._authState.asReadonly();
  readonly isAuthenticated = computed(() => this._authState().isAuthenticated);
  readonly currentUser = computed(() => this._authState().user);
  readonly isAdmin = computed(() => this._authState().user?.role === 'admin');

  login(credentials: LoginRequest): Observable<LoginResponse> {
    return this.mockLogin(credentials).pipe(
      tap((response) => {
        this._authState.set({
          isAuthenticated: true,
          user: response.user,
          token: response.token,
        });

        this.startTokenRefreshTimer();
      }),
      catchError((error) => {
        return throwError(() => error);
      }),
    );
  }

  logout(): void {
    this.refreshSubscription?.unsubscribe();
    this.refreshSubscription = null;

    this._authState.set({
      isAuthenticated: false,
      user: null,
      token: null,
    });
  }

  refreshToken(): Observable<LoginResponse> {
    const currentToken = this._authState().token;
    if (!currentToken) {
      return throwError(() => new Error('No token available'));
    }

    return timer(100).pipe(
      switchMap(() => {
        if (this.isTokenValid(currentToken)) {
          const user = this._authState().user!;
          const newToken = this.generateMockToken();
          const response: LoginResponse = {
            token: newToken,
            user: {
              ...user,
              lastLoginAt: new Date().toISOString(),
            },
            expiresAt: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
          };

          this._authState.set({
            isAuthenticated: true,
            user: response.user,
            token: response.token,
          });

          return of(response);
        } else {
          this.logout();
          return throwError(() => new Error('Token refresh failed'));
        }
      }),
    );
  }

  private startTokenRefreshTimer(): void {
    this.refreshSubscription?.unsubscribe();

    const REFRESH_INTERVAL_MS = 90 * 60 * 1000;
    this.refreshSubscription = timer(REFRESH_INTERVAL_MS)
      .pipe(
        take(1),
        switchMap(() => this.refreshToken()),
        catchError(() => {
          this.logout();
          return of(null);
        }),
      )
      .subscribe();
  }

  private isTokenValid(token: string): boolean {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      const expirationTime = payload.exp * 1000;
      return Date.now() < expirationTime;
    } catch {
      return false;
    }
  }

  private generateMockToken(): string {
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const payload = btoa(
      JSON.stringify({
        sub: 'koopa',
        role: 'admin',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 2 * 60 * 60,
      }),
    );
    const signature = btoa('mock-signature');
    return `${header}.${payload}.${signature}`;
  }

  private mockLogin(credentials: LoginRequest): Observable<LoginResponse> {
    return timer(800).pipe(
      switchMap(() => {
        if (
          credentials.username === MOCK_CREDENTIALS.username &&
          credentials.password === MOCK_CREDENTIALS.password
        ) {
          const user: User = {
            id: '1',
            username: 'koopa',
            email: 'koopa@blog.dev',
            role: 'admin',
            displayName: 'Koopa',
            avatar: '/logo.png',
            createdAt: '2024-01-01T00:00:00Z',
            lastLoginAt: new Date().toISOString(),
          };

          const response: LoginResponse = {
            token: this.generateMockToken(),
            user,
            expiresAt: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
          };

          return of(response);
        } else {
          return throwError(() => ({
            error: 'Invalid credentials',
            message: '用戶名或密碼錯誤',
          }));
        }
      }),
    );
  }
}
