'use client';

import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import { api, ApiError } from '@/lib/api';

export type AuthState = 'loading' | 'setup' | 'login' | 'authenticated';

interface AuthContextValue {
  state: AuthState;
  login: (password: string) => Promise<void>;
  setup: (password: string) => Promise<void>;
  logout: () => Promise<void>;
  checkAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue>({
  state: 'loading',
  login: async () => {},
  setup: async () => {},
  logout: async () => {},
  checkAuth: async () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>('loading');

  const checkAuth = useCallback(async () => {
    try {
      const result = await api.checkAuth();
      if (result.needs_setup) {
        setState('setup');
      } else if (!result.authenticated) {
        setState('login');
      } else {
        setState('authenticated');
      }
    } catch {
      setState('login');
    }
  }, []);

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  const login = async (password: string) => {
    await api.login(password);
    setState('authenticated');
  };

  const setup = async (password: string) => {
    await api.setup(password);
    setState('authenticated');
  };

  const logout = async () => {
    try {
      await api.logout();
    } catch {}
    setState('login');
  };

  return (
    <AuthContext.Provider value={{ state, login, setup, logout, checkAuth }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
