import { Injectable, inject, signal, computed } from '@angular/core';
import { Observable, tap, catchError, throwError } from 'rxjs';
import { ApiService } from './api.service';
import type {
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
  /** Backend validates email allowlist — if authenticated, user is admin */
  readonly isAdmin = computed(() => this._authState().isAuthenticated);
  readonly accessToken = computed(() => this._authState().tokens?.accessToken ?? null);

  /** Handle OAuth callback — store tokens from redirect query params */
  handleOAuthCallback(accessToken: string, refreshToken: string): void {
    const tokens: TokenPair = { accessToken, refreshToken };
    const user = this.decodeUser(accessToken);
    this._authState.set({ isAuthenticated: true, user, tokens });
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
        tap((apiTokens) => this.setTokens(apiTokens)),
        catchError((error) => {
          this.logout();
          return throwError(() => error);
        }),
      );
  }

  /** Parse user info from token pair and update auth state */
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

  /** Decode JWT payload to extract user info */
  private decodeUser(token: string): AuthUser {
    const payload = this.decodeJwt(token);
    return {
      email: payload.email,
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
