'use client';

import { useEffect, useState, useCallback } from 'react';
import { api } from '@/lib/api';
import type { ApiKey, Account } from '@/lib/types';
import { Card } from '@/components/ui/Card';
import { CreateKeyForm } from '@/components/keys/CreateKeyForm';
import { NewKeyBanner } from '@/components/keys/NewKeyBanner';
import { KeysTable } from '@/components/keys/KeysTable';

export default function KeysPage() {
  const [keys, setKeys] = useState<ApiKey[] | null>(null);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [newKey, setNewKey] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [keysRes, accRes] = await Promise.all([api.listKeys(), api.listAccounts()]);
      setKeys(keysRes.keys);
      setAccounts(accRes.accounts);
    } catch {}
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  return (
    <div className="max-w-6xl space-y-6">
      <h2 className="text-xl font-semibold text-text-primary">API Keys</h2>

      <Card>
        <CreateKeyForm
          accounts={accounts}
          onCreated={(key) => { setNewKey(key); refresh(); }}
        />
      </Card>

      {newKey && <NewKeyBanner keyValue={newKey} onDismiss={() => setNewKey(null)} />}

      <KeysTable keys={keys} accounts={accounts} onRefresh={refresh} />
    </div>
  );
}
