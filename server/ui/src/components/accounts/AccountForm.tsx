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
  const [limitUsd, setLimitUsd] = useState(editing?.quota?.monthly_limit_usd?.toString() || '100');
  const [resetDay, setResetDay] = useState(editing?.quota?.reset_day?.toString() || '1');
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
        quota: { monthly_limit_usd: parseFloat(limitUsd) || 100, reset_day: parseInt(resetDay) || 1 },
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
        <div>
          <h3 className="text-sm font-medium text-text-primary mb-2">Quota</h3>
          <div className="grid grid-cols-2 gap-3">
            <Input label="Monthly limit (USD)" type="number" value={limitUsd} onChange={(e) => setLimitUsd(e.target.value)} placeholder="100" />
            <Input label="Reset day" type="number" value={resetDay} onChange={(e) => setResetDay(e.target.value)} placeholder="1" />
          </div>
        </div>
        <div className="flex justify-end gap-2 pt-2">
          <Button variant="ghost" type="button" onClick={onClose}>Cancel</Button>
          <Button type="submit" loading={loading}>{editing ? 'Save' : 'Create'}</Button>
        </div>
      </form>
    </Dialog>
  );
}
