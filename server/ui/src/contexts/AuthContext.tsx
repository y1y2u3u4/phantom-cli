'use client';

import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import { api, ApiError } from '@/lib/api';

export type AuthState = 'loading' | 'setup' | 'login' | 'authenticated';

interface AuthContextValue {
  state: AuthState;
  role: 'admin' | 'member' | null;
  username: string | null;
  isAdmin: boolean;
  login: (password: string, username?: string) => Promise<void>;
  setup: (password: string) => Promise<void>;
  logout: () => Promise<void>;
  checkAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue>({
  state: 'loading',
  role: null,
  username: null,
  isAdmin: false,
  login: async () => {},
  setup: async () => {},
  logout: async () => {},
  checkAuth: async () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>('loading');
  const [role, setRole] = useState<'admin' | 'member' | null>(null);
  const [username, setUsername] = useState<string | null>(null);

  const isAdmin = role === 'admin';

  const checkAuth = useCallback(async () => {
    try {
      const result = await api.checkAuth();
      if (result.needs_setup) {
        setState('setup');
      } else if (!result.authenticated) {
        setState('login');
      } else {
        setRole(result.role || 'admin');
        setUsername(result.username || null);
        setState('authenticated');
      }
    } catch {
      setState('login');
    }
  }, []);

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  const login = async (password: string, loginUsername?: string) => {
    await api.login(password, loginUsername);
    await checkAuth();
  };

  const setup = async (password: string) => {
    await api.setup(password);
    setRole('admin');
    setUsername(null);
    setState('authenticated');
  };

  const logout = async () => {
    try {
      await api.logout();
    } catch {}
    setRole(null);
    setUsername(null);
    setState('login');
  };

  return (
    <AuthContext.Provider value={{ state, role, username, isAdmin, login, setup, logout, checkAuth }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
