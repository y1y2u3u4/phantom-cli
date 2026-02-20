'use client';

import { useState, useCallback } from 'react';
import { usePathname } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import { QuotaAlert } from './QuotaAlert';
import { AuthGuard } from '@/components/auth/AuthGuard';

export function AppShell({ children }: { children: React.ReactNode }) {
  const { state } = useAuth();
  const pathname = usePathname();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const toggleMobileMenu = useCallback(() => setMobileMenuOpen((v) => !v), []);
  const closeMobileMenu = useCallback(() => setMobileMenuOpen(false), []);

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
      <Header onMenuToggle={toggleMobileMenu} />
      {state === 'authenticated' ? (
        <>
          <QuotaAlert />
          <div className="flex flex-1">
            <Sidebar mobileOpen={mobileMenuOpen} onClose={closeMobileMenu} />
            <main className="flex-1 p-6 overflow-auto">{children}</main>
          </div>
        </>
      ) : (
        <AuthGuard>{children}</AuthGuard>
      )}
    </div>
  );
}
