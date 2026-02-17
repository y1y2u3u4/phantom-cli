'use client';

import { useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { Card } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { ApiError } from '@/lib/api';

export function LoginForm() {
  const { login } = useAuth();
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!password) { setError('Please enter your password.'); return; }

    setLoading(true);
    try {
      await login(password);
    } catch (err: any) {
      if (err instanceof ApiError && err.status === 401) {
        setError('Incorrect password. Please try again.');
      } else if (err instanceof ApiError && err.status === 429) {
        setError('Too many login attempts. Please wait and try again.');
      } else {
        setError(err.message || 'Login failed.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="w-full max-w-sm">
      <div className="text-center mb-6">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="mx-auto text-accent mb-3">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <h2 className="text-lg font-semibold text-text-primary">Phantom Console</h2>
        <p className="text-sm text-text-secondary mt-1">Enter your master password</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {error && <Alert type="error" message={error} />}
        <Input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Master password"
          autoFocus
        />
        <Button type="submit" loading={loading} loadingText="Signing in..." className="w-full">
          Sign In
        </Button>
      </form>
    </Card>
  );
}
