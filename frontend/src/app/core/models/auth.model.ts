export interface LoginRequest {
  email: string;
  password: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface AuthUser {
  id: string;
  email: string;
  role: 'admin' | 'user';
}

export interface AuthState {
  isAuthenticated: boolean;
  user: AuthUser | null;
  tokens: TokenPair | null;
}
