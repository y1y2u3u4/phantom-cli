'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import type { Account } from '@/lib/types';
import { formatUSD } from '@/lib/utils';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { TestConnection } from './TestConnection';
import { CredentialUpload } from './CredentialUpload';

interface AccountCardProps {
  account: Account;
  onEdit: () => void;
  onRefresh: () => void;
}

export function AccountCard({ account, onEdit, onRefresh }: AccountCardProps) {
  const [showCreds, setShowCreds] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const proxy = account.upstream_proxy;
  const quota = account.quota;
  const limit = quota.monthly_limit_usd || 100;
  const used = limit - account.estimated_remaining_usd;
  const pct = Math.min(100, Math.max(0, (used / limit) * 100));
  const barColor = pct > 80 ? 'bg-danger' : pct > 50 ? 'bg-yellow-500' : 'bg-success';

  const handleDelete = async () => {
    setDeleting(true);
    try { await api.deleteAccount(account.id); onRefresh(); } catch {} finally { setDeleting(false); }
  };

  return (
    <>
      <Card className="space-y-4">
        <div className="flex items-start justify-between">
          <div>
            <h3 className="text-sm font-semibold text-text-primary">{account.name}</h3>
            <p className="text-xs text-text-secondary mt-0.5">
              {proxy.type === 'direct' ? 'Direct connection' : `${proxy.type.toUpperCase()} ${proxy.host}:${proxy.port}`}
              {proxy.has_auth && ' (auth)'}
            </p>
          </div>
          <Badge variant={account.status as any}>{account.status}</Badge>
        </div>

        {/* Quota progress */}
        <div>
          <div className="flex justify-between text-xs text-text-secondary mb-1">
            <span>Quota: {formatUSD(used)} / {formatUSD(limit)}</span>
            <span>{formatUSD(account.estimated_remaining_usd)} remaining</span>
          </div>
          <div className="h-1.5 bg-border rounded-full overflow-hidden">
            <div className={`h-full ${barColor} rounded-full transition-all`} style={{ width: `${pct}%` }} />
          </div>
        </div>

        {/* Credentials status */}
        <div className="flex items-center gap-1.5 text-xs">
          {account.has_credentials ? (
            <><span className="text-success">{'\u2713'}</span><span className="text-text-secondary">Credentials uploaded</span></>
          ) : (
            <><span className="text-yellow-500">{'\u26A0'}</span><span className="text-yellow-500">No credentials</span></>
          )}
        </div>

        {/* Actions */}
        <div className="flex flex-wrap gap-2 pt-1 border-t border-border">
          <Button variant="ghost" size="sm" onClick={onEdit}>Edit</Button>
          <TestConnection accountId={account.id} />
          <Button variant="ghost" size="sm" onClick={() => setShowCreds(true)}>Upload Creds</Button>
          {confirmDelete ? (
            <div className="flex items-center gap-2 ml-auto">
              <span className="text-xs text-danger">Sure?</span>
              <Button variant="ghost" size="sm" onClick={() => setConfirmDelete(false)}>No</Button>
              <Button variant="danger" size="sm" loading={deleting} onClick={handleDelete}>Yes</Button>
            </div>
          ) : (
            <Button variant="danger" size="sm" className="ml-auto" onClick={() => setConfirmDelete(true)}>Delete</Button>
          )}
        </div>
      </Card>

      <CredentialUpload open={showCreds} onClose={() => setShowCreds(false)} accountId={account.id} onUploaded={onRefresh} />
    </>
  );
}
