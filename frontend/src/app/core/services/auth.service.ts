import { Injectable, inject, signal, computed } from '@angular/core';
import { Observable, tap, catchError, throwError } from 'rxjs';
import { ApiService } from './api.service';
import type {
  LoginRequest,
  TokenPair,
  AuthUser,
  AuthState,
  ApiTokenResponse,
  JwtPayload,
} from '../models';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly api = inject(ApiService);

  private readonly _authState = signal<AuthState>({
    isAuthenticated: false,
    user: null,
    tokens: null,
  });

  readonly authState = this._authState.asReadonly();
  readonly isAuthenticated = computed(() => this._authState().isAuthenticated);
  readonly currentUser = computed(() => this._authState().user);
  readonly isAdmin = computed(() => this._authState().user?.role === 'admin');
  readonly accessToken = computed(() => this._authState().tokens?.accessToken ?? null);

  login(credentials: LoginRequest): Observable<ApiTokenResponse> {
    return this.api
      .postData<ApiTokenResponse>('/api/auth/login', {
        email: credentials.email,
        password: credentials.password,
      })
      .pipe(
        tap((tokens) => this.setTokens(tokens)),
        catchError((error) => {
          const message =
            error.status === 401
              ? '電子郵件或密碼錯誤'
              : '登入失敗，請稍後再試';
          return throwError(() => new Error(message));
        }),
      );
  }

  logout(): void {
    this._authState.set({
      isAuthenticated: false,
      user: null,
      tokens: null,
    });
  }

  refreshToken(): Observable<ApiTokenResponse> {
    const refreshToken = this._authState().tokens?.refreshToken;
    if (!refreshToken) {
      return throwError(() => new Error('No refresh token'));
    }

    return this.api
      .postData<ApiTokenResponse>('/api/auth/refresh', {
        refresh_token: refreshToken,
      })
      .pipe(
        tap((tokens) => this.setTokens(tokens)),
        catchError((error) => {
          this.logout();
          return throwError(() => error);
        }),
      );
  }

  /** 從 token pair 解析使用者資訊並更新狀態 */
  private setTokens(apiTokens: ApiTokenResponse): void {
    const tokens: TokenPair = {
      accessToken: apiTokens.access_token,
      refreshToken: apiTokens.refresh_token,
    };

    const user = this.decodeUser(tokens.accessToken);

    this._authState.set({
      isAuthenticated: true,
      user,
      tokens,
    });
  }

  /** 解碼 JWT payload 取得使用者資訊 */
  private decodeUser(token: string): AuthUser {
    const payload = this.decodeJwt(token);
    return {
      id: payload.user_id,
      email: payload.email,
      role: payload.role as 'admin' | 'user',
    };
  }

  private decodeJwt(token: string): JwtPayload {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join(''),
    );
    return JSON.parse(jsonPayload) as JwtPayload;
  }
}
