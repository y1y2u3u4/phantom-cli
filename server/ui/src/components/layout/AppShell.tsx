'use client';

import { useAuth } from '@/contexts/AuthContext';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import { AuthGuard } from '@/components/auth/AuthGuard';

export function AppShell({ children }: { children: React.ReactNode }) {
  const { state } = useAuth();

  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      {state === 'authenticated' ? (
        <div className="flex flex-1">
          <Sidebar />
          <main className="flex-1 p-6 overflow-auto">{children}</main>
        </div>
      ) : (
        <AuthGuard>{children}</AuthGuard>
      )}
    </div>
  );
}
