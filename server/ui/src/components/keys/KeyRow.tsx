'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import type { ApiKey, Account } from '@/lib/types';
import { formatDate, formatUSD } from '@/lib/utils';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';

interface KeyRowProps {
  keyData: ApiKey;
  accounts: Account[];
  onRefresh: () => void;
}

export function KeyRow({ keyData, accounts, onRefresh }: KeyRowProps) {
  const { isAdmin } = useAuth();
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [assigning, setAssigning] = useState(false);

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await api.deleteKey(keyData.id);
      onRefresh();
    } catch { setDeleting(false); }
  };

  const handleAssign = async (accId: string) => {
    setAssigning(true);
    try {
      if (accId) {
        await api.assignKeyAccount(keyData.id, accId);
      } else {
        await api.unassignKeyAccount(keyData.id);
      }
      onRefresh();
    } catch {} finally { setAssigning(false); }
  };

  const usage = keyData.usage_this_month;

  return (
    <>
      <tr className="border-t border-border hover:bg-border/20 transition-colors">
        <td className="px-4 py-3 text-sm font-medium text-text-primary">{keyData.name}</td>
        <td className="px-4 py-3">
          <code className="text-xs text-text-secondary font-mono">{keyData.masked_key}</code>
        </td>
        <td className="px-4 py-3">
          {keyData.account_name ? (
            <span className="text-sm text-text-primary">{keyData.account_name}</span>
          ) : (
            <Badge variant="info">Auto</Badge>
          )}
        </td>
        <td className="px-4 py-3 text-xs text-text-secondary">
          {formatDate(keyData.created_at) || '-'}
        </td>
        <td className="px-4 py-3 text-xs text-text-secondary">
          {keyData.last_used_at ? formatDate(keyData.last_used_at) : <span className="opacity-50">Never</span>}
        </td>
        <td className="px-4 py-3 text-xs text-text-secondary">
          {usage ? (
            <span>{usage.connections} conn / {formatUSD(usage.estimated_cost_usd)}</span>
          ) : '-'}
        </td>
        <td className="px-4 py-3 text-right">
          <div className="flex items-center justify-end gap-2">
            {isAdmin && (
              <select
                value={keyData.account_id || ''}
                onChange={(e) => handleAssign(e.target.value)}
                disabled={assigning}
                className="px-2 py-1 text-xs bg-[var(--input-bg)] border border-[var(--input-border)] rounded text-text-primary focus:outline-none"
              >
                <option value="">Auto</option>
                {accounts.map((a) => (
                  <option key={a.id} value={a.id}>{a.name}</option>
                ))}
              </select>
            )}
            <Button variant="danger" size="sm" onClick={() => setConfirmDelete(true)}>
              Delete
            </Button>
          </div>
        </td>
      </tr>
      {confirmDelete && (
        <tr className="bg-danger/5 border-t border-danger/20">
          <td colSpan={7} className="px-4 py-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-text-primary">
                Delete <strong>{keyData.name}</strong>? This cannot be undone.
              </span>
              <div className="flex gap-2">
                <Button variant="ghost" size="sm" onClick={() => setConfirmDelete(false)}>Cancel</Button>
                <Button variant="danger" size="sm" loading={deleting} onClick={handleDelete}>Delete</Button>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
