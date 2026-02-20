'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { api, ApiError } from '@/lib/api';
import { Card } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { Spinner } from '@/components/ui/Spinner';

type PageState = 'loading' | 'valid' | 'invalid' | 'registered';

export default function InvitePage() {
  const router = useRouter();
  const [token, setToken] = useState('');
  const [pageState, setPageState] = useState<PageState>('loading');
  const [invalidMsg, setInvalidMsg] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Extract token from URL path: /invite/inv_xxx
    const match = window.location.pathname.match(/^\/invite\/(.+)$/);
    if (!match) {
      setInvalidMsg('No invite token found in URL.');
      setPageState('invalid');
      return;
    }
    const t = decodeURIComponent(match[1]);
    setToken(t);

    api.checkInvite(t).then((res) => {
      if (res.valid) {
        setPageState('valid');
      } else {
        setInvalidMsg(res.error || 'This invite link is invalid or expired.');
        setPageState('invalid');
      }
    }).catch((err) => {
      setInvalidMsg(err.message || 'Failed to verify invite link.');
      setPageState('invalid');
    });
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    const trimmedUser = username.trim();
    if (!trimmedUser) { setError('Please enter a username.'); return; }
    if (trimmedUser.length < 3) { setError('Username must be at least 3 characters.'); return; }
    if (!password) { setError('Please enter a password.'); return; }
    if (password.length < 6) { setError('Password must be at least 6 characters.'); return; }
    if (password !== confirmPassword) { setError('Passwords do not match.'); return; }

    setLoading(true);
    try {
      await api.registerInvite(token, trimmedUser, password);
      setPageState('registered');
      // Auto-login and redirect after a short delay
      try {
        await api.login(password, trimmedUser);
        setTimeout(() => router.push('/keys'), 1500);
      } catch {
        // If auto-login fails, user can login manually
        setTimeout(() => router.push('/'), 3000);
      }
    } catch (err: any) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Registration failed. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="w-full max-w-sm">
      <div className="text-center mb-6">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="mx-auto text-accent mb-3">
          <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/>
          <circle cx="9" cy="7" r="4"/>
          <line x1="19" y1="8" x2="19" y2="14"/>
          <line x1="22" y1="11" x2="16" y2="11"/>
        </svg>
        <h2 className="text-lg font-semibold text-text-primary">Join Phantom</h2>
        <p className="text-sm text-text-secondary mt-1">Create your team account</p>
      </div>

      {pageState === 'loading' && (
        <div className="flex items-center justify-center py-8">
          <Spinner size={24} />
          <span className="ml-2 text-sm text-text-secondary">Verifying invite link...</span>
        </div>
      )}

      {pageState === 'invalid' && (
        <Alert type="error" message={invalidMsg} />
      )}

      {pageState === 'registered' && (
        <Alert type="success" message="Account created! Redirecting to dashboard..." />
      )}

      {pageState === 'valid' && (
        <form onSubmit={handleSubmit} className="space-y-4">
          {error && <Alert type="error" message={error} />}
          <Input
            label="Username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Choose a username"
            autoFocus
          />
          <Input
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Choose a password"
          />
          <Input
            label="Confirm Password"
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Confirm your password"
          />
          <Button type="submit" loading={loading} loadingText="Creating account..." className="w-full">
            Create Account
          </Button>
        </form>
      )}
    </Card>
  );
}
