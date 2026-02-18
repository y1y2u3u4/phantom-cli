'use client';

import { useState, useEffect } from 'react';
import { api } from '@/lib/api';
import type { Account, AccountQuotaResponse } from '@/lib/types';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Spinner } from '@/components/ui/Spinner';
import { TestConnection } from './TestConnection';
import { CredentialUpload } from './CredentialUpload';

interface AccountCardProps {
  account: Account;
  onEdit: () => void;
  onRefresh: () => void;
}

function barColor(pct: number): string {
  if (pct > 80) return 'bg-danger';
  if (pct > 50) return 'bg-yellow-500';
  return 'bg-success';
}

function QuotaBar({ label, pct, resetsIn }: { label: string; pct: number; resetsIn: string | null }) {
  return (
    <div>
      <div className="flex justify-between text-xs text-text-secondary mb-0.5">
        <span>{label}</span>
        <span>{pct}% used{resetsIn ? ` \u00B7 resets ${resetsIn}` : ''}</span>
      </div>
      <div className="h-1.5 bg-border rounded-full overflow-hidden">
        <div className={`h-full ${barColor(pct)} rounded-full transition-all`} style={{ width: `${Math.min(100, pct)}%` }} />
      </div>
    </div>
  );
}

export function AccountCard({ account, onEdit, onRefresh }: AccountCardProps) {
  const [showCreds, setShowCreds] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [quota, setQuota] = useState<AccountQuotaResponse | null>(null);
  const [quotaLoading, setQuotaLoading] = useState(false);

  const proxy = account.upstream_proxy;

  // Load real quota async when card mounts (only if account has credentials)
  useEffect(() => {
    if (!account.has_credentials) return;
    let cancelled = false;
    setQuotaLoading(true);
    api.getAccountQuota(account.id)
      .then((res) => { if (!cancelled) setQuota(res); })
      .catch(() => {})
      .finally(() => { if (!cancelled) setQuotaLoading(false); });
    return () => { cancelled = true; };
  }, [account.id, account.has_credentials]);

  const handleDelete = async () => {
    setDeleting(true);
    try { await api.deleteAccount(account.id); onRefresh(); } catch {} finally { setDeleting(false); }
  };

  // Subscription type badge
  const subType = quota?.subscription_type || account.real_quota?.subscription_type;

  return (
    <>
      <Card className="space-y-3">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-text-primary">{account.name}</h3>
              {subType && (
                <span className="text-[10px] font-medium uppercase px-1.5 py-0.5 rounded bg-accent/10 text-accent">
                  {subType}
                </span>
              )}
            </div>
            <p className="text-xs text-text-secondary mt-0.5">
              {proxy.type === 'direct' ? 'Direct connection' : `${proxy.type.toUpperCase()} ${proxy.host}:${proxy.port}`}
              {proxy.has_auth && ' (auth)'}
            </p>
          </div>
          <Badge variant={account.status as any}>{account.status}</Badge>
        </div>

        {/* Quota bars */}
        {account.has_credentials ? (
          quotaLoading && !quota ? (
            <div className="flex items-center gap-2 text-xs text-text-secondary py-1">
              <Spinner size={12} /> Loading quota...
            </div>
          ) : quota && !quota.error ? (
            <div className="space-y-2">
              {quota.five_hour && (
                <QuotaBar label="Session (5h)" pct={quota.five_hour.utilization} resetsIn={quota.five_hour.resets_in} />
              )}
              {quota.seven_day && (
                <QuotaBar label="Weekly (7d)" pct={quota.seven_day.utilization} resetsIn={quota.seven_day.resets_in} />
              )}
              {quota.seven_day_opus && (
                <QuotaBar label="Opus (7d)" pct={quota.seven_day_opus.utilization} resetsIn={quota.seven_day_opus.resets_in} />
              )}
              {quota.seven_day_sonnet && (
                <QuotaBar label="Sonnet (7d)" pct={quota.seven_day_sonnet.utilization} resetsIn={quota.seven_day_sonnet.resets_in} />
              )}
              {!quota.five_hour && !quota.seven_day && (
                <p className="text-xs text-text-secondary">No active usage limits</p>
              )}
            </div>
          ) : quota?.error ? (
            <p className="text-xs text-danger">{quota.error}</p>
          ) : null
        ) : (
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-yellow-500">{'\u26A0'}</span>
            <span className="text-yellow-500">No credentials uploaded</span>
          </div>
        )}

        {/* Credentials status (when has credentials) */}
        {account.has_credentials && (
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-success">{'\u2713'}</span>
            <span className="text-text-secondary">Credentials uploaded</span>
          </div>
        )}

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
