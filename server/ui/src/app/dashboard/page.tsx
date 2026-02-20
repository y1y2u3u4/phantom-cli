'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import { ConnectionMonitor } from '@/components/dashboard/ConnectionMonitor';

export default function DashboardPage() {
  const { isAdmin } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isAdmin) router.replace('/keys');
  }, [isAdmin, router]);

  if (!isAdmin) return null;

  return (
    <div className="max-w-6xl space-y-6">
      <h2 className="text-xl font-semibold text-text-primary">Dashboard</h2>
      <ConnectionMonitor />
    </div>
  );
}
