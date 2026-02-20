'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';

export default function HomePage() {
  const router = useRouter();
  const { state, isAdmin } = useAuth();

  useEffect(() => {
    if (state === 'authenticated') {
      router.replace(isAdmin ? '/dashboard' : '/keys');
    }
  }, [state, isAdmin, router]);

  // AuthGuard handles setup/login states via AppShell
  return null;
}
