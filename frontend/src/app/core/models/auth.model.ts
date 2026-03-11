export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface AuthUser {
  email: string;
}

export interface AuthState {
  isAuthenticated: boolean;
  user: AuthUser | null;
  tokens: TokenPair | null;
}
