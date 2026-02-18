'use client';

import { useEffect, useState, useCallback } from 'react';
import { api } from '@/lib/api';
import type { Account } from '@/lib/types';
import { Button } from '@/components/ui/Button';
import { Spinner } from '@/components/ui/Spinner';
import { Skeleton } from '@/components/ui/Skeleton';
import { Card } from '@/components/ui/Card';
import { AccountCard } from '@/components/accounts/AccountCard';
import { AccountForm } from '@/components/accounts/AccountForm';

export default function AccountsPage() {
  const [accounts, setAccounts] = useState<Account[] | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<Account | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const res = await api.listAccounts();
      setAccounts(res.accounts);
    } catch {}
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const openCreate = () => { setEditing(null); setFormOpen(true); };
  const openEdit = (a: Account) => { setEditing(a); setFormOpen(true); };

  const handleRefreshQuota = async () => {
    setRefreshing(true);
    try { await api.refreshQuota(); } catch {}
    // Wait a moment for background queries, then reload
    setTimeout(() => { refresh(); setRefreshing(false); }, 3000);
  };

  return (
    <div className="max-w-6xl space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-text-primary">Accounts</h2>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={handleRefreshQuota} disabled={refreshing}>
            {refreshing ? <><Spinner size={14} /> Refreshing...</> : 'Refresh Quota'}
          </Button>
          <Button onClick={openCreate}>Add Account</Button>
        </div>
      </div>

      {accounts === null ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[1,2,3].map((i) => (
            <Card key={i} className="space-y-3">
              <Skeleton className="h-5 w-32" /><Skeleton className="h-3 w-48" />
              <Skeleton className="h-1.5 w-full" /><Skeleton className="h-3 w-24" />
            </Card>
          ))}
        </div>
      ) : accounts.length === 0 ? (
        <Card className="p-12 text-center">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="mx-auto text-text-secondary/50 mb-3">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>
          </svg>
          <p className="text-sm text-text-secondary mb-3">No accounts yet. Add one to start routing through upstream proxies.</p>
          <Button onClick={openCreate}>Add Account</Button>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {accounts.map((a) => (
            <AccountCard key={a.id} account={a} onEdit={() => openEdit(a)} onRefresh={refresh} />
          ))}
        </div>
      )}

      <AccountForm open={formOpen} onClose={() => setFormOpen(false)} onSaved={refresh} editing={editing} />
    </div>
  );
}
