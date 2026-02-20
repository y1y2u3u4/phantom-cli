'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/contexts/ToastContext';
import type { Account } from '@/lib/types';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Alert } from '@/components/ui/Alert';

interface CreateKeyFormProps {
  accounts: Account[];
  onCreated: (key: string) => void;
}

export function CreateKeyForm({ accounts, onCreated }: CreateKeyFormProps) {
  const { isAdmin } = useAuth();
  const toast = useToast();
  const [name, setName] = useState('');
  const [accountId, setAccountId] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    const trimmed = name.trim();
    if (!trimmed) { setError('Please enter a name for the API key.'); return; }

    setLoading(true);
    try {
      const result = await api.createKey(trimmed, accountId || undefined);
      setName('');
      setAccountId('');
      toast.success('API key created successfully.');
      onCreated(result.key);
    } catch (err: any) {
      setError(err.message || 'Failed to create key.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-3">
      {error && <Alert type="error" message={error} />}
      <div className="flex gap-3 items-end">
        <div className="flex-1">
          <Input
            label="Key name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Team member name"
          />
        </div>
        {isAdmin && accounts.length > 0 && (
          <div className="w-48">
            <label className="block text-xs font-medium text-text-secondary mb-1.5">Account</label>
            <select
              value={accountId}
              onChange={(e) => setAccountId(e.target.value)}
              className="w-full px-3 py-2 text-sm bg-[var(--input-bg)] border border-[var(--input-border)] rounded-lg text-text-primary focus:outline-none focus:ring-2 focus:ring-accent/50"
            >
              <option value="">Auto (round-robin)</option>
              {accounts.map((a) => (
                <option key={a.id} value={a.id}>{a.name}</option>
              ))}
            </select>
          </div>
        )}
        <Button type="submit" loading={loading} loadingText="Creating...">
          Create Key
        </Button>
      </div>
    </form>
  );
}
