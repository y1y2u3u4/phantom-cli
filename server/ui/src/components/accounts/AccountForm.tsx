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
  const [sessionMax, setSessionMax] = useState<string>(
    String(editing?.quota?.session_max_pct ?? 80)
  );
  const [dailyBudget, setDailyBudget] = useState<string>(
    String(editing?.quota?.daily_budget_pct ?? 10)
  );
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!name.trim()) { setError('Account name is required.'); return; }

    const parsedSession = parseInt(sessionMax.trim() || '80', 10);
    const parsedBudget = parseInt(dailyBudget.trim() || '10', 10);
    if (isNaN(parsedSession) || parsedSession < 1 || parsedSession > 100) {
      setError('Session max must be 1-100.');
      return;
    }
    if (isNaN(parsedBudget) || parsedBudget < 1 || parsedBudget > 100) {
      setError('Daily budget must be 1-100.');
      return;
    }

    setLoading(true);
    try {
      const quotaObj = {
        ...(editing?.quota || {}),
        session_max_pct: parsedSession,
        daily_budget_pct: parsedBudget,
      };
      if (editing) {
        await api.updateAccount(editing.id, {
          name: name.trim(),
          upstream_proxy: proxy,
          quota: quotaObj,
        });
      } else {
        await api.createAccount({
          name: name.trim(),
          upstream_proxy: proxy,
          quota: quotaObj,
        });
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
          <h3 className="text-sm font-medium text-text-primary mb-2">Usage Limits</h3>
          <div className="grid grid-cols-2 gap-3">
            <Input
              label="Session Max %"
              type="number"
              value={sessionMax}
              onChange={(e) => setSessionMax(e.target.value)}
              min={1}
              max={100}
            />
            <Input
              label="Daily Budget %"
              type="number"
              value={dailyBudget}
              onChange={(e) => setDailyBudget(e.target.value)}
              min={1}
              max={100}
            />
          </div>
          <p className="text-xs text-text-secondary mt-1">Session Max: rotate when 5h session utilization reaches this %. Daily Budget: max daily increase in 7d weekly utilization.</p>
        </div>
        <div className="flex justify-end gap-2 pt-2">
          <Button variant="ghost" type="button" onClick={onClose}>Cancel</Button>
          <Button type="submit" loading={loading}>{editing ? 'Save' : 'Create'}</Button>
        </div>
      </form>
    </Dialog>
  );
}
