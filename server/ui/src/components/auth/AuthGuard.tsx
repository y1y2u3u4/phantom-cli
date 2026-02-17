'use client';

import { useAuth } from '@/contexts/AuthContext';
import { SetupForm } from './SetupForm';
import { LoginForm } from './LoginForm';
import { Spinner } from '@/components/ui/Spinner';

export function AuthGuard({ children }: { children: React.ReactNode }) {
  const { state } = useAuth();

  if (state === 'loading') {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <Spinner size={32} />
          <span className="text-sm text-text-secondary">Connecting to Phantom server...</span>
        </div>
      </div>
    );
  }

  if (state === 'setup') {
    return (
      <div className="flex-1 flex items-center justify-center p-4">
        <SetupForm />
      </div>
    );
  }

  if (state === 'login') {
    return (
      <div className="flex-1 flex items-center justify-center p-4">
        <LoginForm />
      </div>
    );
  }

  return <>{children}</>;
}
