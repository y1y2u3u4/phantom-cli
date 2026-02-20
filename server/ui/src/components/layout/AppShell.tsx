'use client';

import { usePathname } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import { QuotaAlert } from './QuotaAlert';
import { AuthGuard } from '@/components/auth/AuthGuard';

export function AppShell({ children }: { children: React.ReactNode }) {
  const { state } = useAuth();
  const pathname = usePathname();

  const isInvitePage = pathname.startsWith('/invite');

  if (isInvitePage) {
    return (
      <div className="min-h-screen flex flex-col">
        <Header />
        <main className="flex-1 flex items-center justify-center p-6">
          {children}
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col">
      <Header />
      {state === 'authenticated' ? (
        <>
          <QuotaAlert />
          <div className="flex flex-1">
            <Sidebar />
            <main className="flex-1 p-6 overflow-auto">{children}</main>
          </div>
        </>
      ) : (
        <AuthGuard>{children}</AuthGuard>
      )}
    </div>
  );
}
