export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  user: User;
  expiresAt: string;
}

export interface User {
  id: string;
  username: string;
  email?: string;
  role: 'admin' | 'user';
  displayName: string;
  avatar?: string;
  createdAt: string;
  lastLoginAt?: string;
}

export interface AuthState {
  isAuthenticated: boolean;
  user: User | null;
  token: string | null;
}