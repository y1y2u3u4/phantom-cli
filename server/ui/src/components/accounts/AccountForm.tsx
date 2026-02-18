'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import type { Account, UpstreamProxyInput } from '@/lib/types';
import { Dialog } from '@/components/ui/Dialog';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';
import { ProxyConfig } from './ProxyConfig';

interface AccountFormProps {
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
  editing?: Account | null;
}

export function AccountForm({ open, onClose, onSaved, editing }: AccountFormProps) {
  const [name, setName] = useState(editing?.name || '');
  const [proxy, setProxy] = useState<UpstreamProxyInput>({
    type: editing?.upstream_proxy?.type || 'direct',
    host: editing?.upstream_proxy?.host || '',
    port: editing?.upstream_proxy?.port || 0,
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!name.trim()) { setError('Account name is required.'); return; }

    setLoading(true);
    try {
      const payload = {
        name: name.trim(),
        upstream_proxy: proxy,
      };
      if (editing) {
        await api.updateAccount(editing.id, payload);
      } else {
        await api.createAccount(payload);
      }
      onSaved();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to save account.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} title={editing ? 'Edit Account' : 'Create Account'}>
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && <Alert type="error" message={error} />}
        <Input label="Account name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. US Proxy Account" autoFocus />
        <div>
          <h3 className="text-sm font-medium text-text-primary mb-2">Upstream Proxy</h3>
          <ProxyConfig value={proxy} onChange={setProxy} />
        </div>
        <p className="text-xs text-text-secondary">Quota is determined by your Anthropic subscription (5h session + 7d weekly limits). Upload credentials after creating the account.</p>
        <div className="flex justify-end gap-2 pt-2">
          <Button variant="ghost" type="button" onClick={onClose}>Cancel</Button>
          <Button type="submit" loading={loading}>{editing ? 'Save' : 'Create'}</Button>
        </div>
      </form>
    </Dialog>
  );
}
