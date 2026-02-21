'use client';

import { useState, useEffect, useCallback } from 'react';
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

function barTextColor(pct: number): string {
  if (pct > 80) return 'text-danger';
  if (pct > 50) return 'text-yellow-500';
  return 'text-success';
}

function QuotaBar({ label, pct, resetsIn }: { label: string; pct: number; resetsIn: string | null }) {
  return (
    <div>
      <div className="flex justify-between text-xs mb-0.5">
        <span className="text-text-secondary">{label}</span>
        <span className={barTextColor(pct)}>
          {pct}%{resetsIn ? <span className="text-text-secondary/60"> · resets {resetsIn}</span> : ''}
        </span>
      </div>
      <div className="h-1.5 bg-border rounded-full overflow-hidden">
        <div className={`h-full ${barColor(pct)} rounded-full transition-all`} style={{ width: `${Math.min(100, pct)}%` }} />
      </div>
    </div>
  );
}

function timeAgo(ts: number | null | undefined): string {
  if (!ts) return '';
  const diffSec = Math.floor(Date.now() / 1000 - ts);
  if (diffSec < 60) return 'just now';
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

export function AccountCard({ account, onEdit, onRefresh }: AccountCardProps) {
  const [showCreds, setShowCreds] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [quota, setQuota] = useState<AccountQuotaResponse | null>(null);
  const [quotaLoading, setQuotaLoading] = useState(false);

  const proxy = account.upstream_proxy;

  const loadQuota = useCallback(async () => {
    if (!account.has_credentials) return;
    setQuotaLoading(true);
    try {
      const res = await api.getAccountQuota(account.id);
      setQuota(res);
    } catch {}
    setQuotaLoading(false);
  }, [account.id, account.has_credentials]);

  // Load real quota async when card mounts
  useEffect(() => { loadQuota(); }, [loadQuota]);

  const handleDelete = async () => {
    setDeleting(true);
    try { await api.deleteAccount(account.id); onRefresh(); } catch {} finally { setDeleting(false); }
  };

  // Subscription type badge
  const subType = quota?.subscription_type || account.real_quota?.subscription_type;

  const hasQuotaData = quota && !quota.error && (quota.five_hour || quota.seven_day);

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
          ) : hasQuotaData ? (
            <div className="space-y-2">
              {quota.five_hour && (
                <QuotaBar label="Session (5h)" pct={quota.five_hour.utilization} resetsIn={quota.five_hour.resets_in} />
              )}
              {quota.seven_day && (
                <QuotaBar label="Weekly (7d)" pct={quota.seven_day.utilization} resetsIn={quota.seven_day.resets_in} />
              )}
              {quota.seven_day_opus && (
                <QuotaBar label="Opus (7d)" pct={quota.seven_day_opus.utilization} resetsIn={null} />
              )}
              {quota.seven_day_sonnet && (
                <QuotaBar label="Sonnet (7d)" pct={quota.seven_day_sonnet.utilization} resetsIn={null} />
              )}
              {/* Queried timestamp */}
              {quota.queried_at && (
                <div className="flex items-center justify-between text-[10px] text-text-secondary/50 pt-0.5">
                  <span>Queried {timeAgo(quota.queried_at)}</span>
                  <button
                    onClick={loadQuota}
                    disabled={quotaLoading}
                    className="hover:text-text-secondary transition-colors disabled:opacity-50"
                    title="Refresh quota"
                  >
                    {quotaLoading ? <Spinner size={10} /> : (
                      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M21 2v6h-6"/><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M3 22v-6h6"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/>
                      </svg>
                    )}
                  </button>
                </div>
              )}
            </div>
          ) : quota?.error ? (
            <p className="text-xs text-danger">{quota.error}</p>
          ) : (
            <p className="text-xs text-text-secondary">No active usage limits</p>
          )
        ) : (
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-yellow-500">{'\u26A0'}</span>
            <span className="text-yellow-500">No credentials uploaded</span>
          </div>
        )}

        {/* Usage limits info */}
        {account.quota && (account.quota.session_max_pct || account.quota.daily_budget_pct) && (
          <div className="space-y-1">
            {account.current_session_pct != null && (
              <QuotaBar
                label={`Session (max ${account.quota.session_max_pct ?? 80}%)`}
                pct={account.current_session_pct}
                resetsIn={null}
              />
            )}
            {account.daily_baseline_weekly_pct != null && account.current_weekly_pct != null && (
              <div>
                <div className="flex justify-between text-xs mb-0.5">
                  <span className="text-text-secondary">Daily Budget (+{account.quota.daily_budget_pct ?? 10}%/day)</span>
                  <span className={barTextColor(Math.round(((account.current_weekly_pct - account.daily_baseline_weekly_pct) / (account.quota.daily_budget_pct ?? 10)) * 100))}>
                    +{Math.max(0, account.current_weekly_pct - account.daily_baseline_weekly_pct).toFixed(1)}% / {account.quota.daily_budget_pct ?? 10}%
                  </span>
                </div>
                <div className="h-1.5 bg-border rounded-full overflow-hidden">
                  <div
                    className={`h-full ${barColor(Math.round(((account.current_weekly_pct - account.daily_baseline_weekly_pct) / (account.quota.daily_budget_pct ?? 10)) * 100))} rounded-full transition-all`}
                    style={{ width: `${Math.min(100, Math.max(0, (account.current_weekly_pct - account.daily_baseline_weekly_pct) / (account.quota.daily_budget_pct ?? 10)) * 100)}%` }}
                  />
                </div>
              </div>
            )}
            <div className="text-[10px] text-text-secondary/60">
              Today: {account.daily_connections_today || 0} connections
            </div>
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
