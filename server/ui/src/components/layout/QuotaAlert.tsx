'use client';

import { useEffect, useState, useCallback } from 'react';
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import type { Account } from '@/lib/types';

interface AlertInfo {
  name: string;
  type: 'warning' | 'critical';
  detail: string;
}

const WARN_THRESHOLD = 80;
const CRITICAL_THRESHOLD = 95;

export function QuotaAlert() {
  const { state } = useAuth();
  const [alerts, setAlerts] = useState<AlertInfo[]>([]);
  const [dismissed, setDismissed] = useState(false);

  const check = useCallback(async () => {
    if (state !== 'authenticated') return;
    try {
      const res = await api.listAccounts();
      const found: AlertInfo[] = [];
      for (const a of res.accounts) {
        const q = a.real_quota;
        if (!q) continue;
        const maxPct = Math.max(q.five_hour_pct ?? 0, q.seven_day_pct ?? 0);
        if (maxPct >= CRITICAL_THRESHOLD) {
          found.push({
            name: a.name,
            type: 'critical',
            detail: `Session ${q.five_hour_pct ?? '?'}% · Weekly ${q.seven_day_pct ?? '?'}%`,
          });
        } else if (maxPct >= WARN_THRESHOLD) {
          found.push({
            name: a.name,
            type: 'warning',
            detail: `Session ${q.five_hour_pct ?? '?'}% · Weekly ${q.seven_day_pct ?? '?'}%`,
          });
        }
      }
      setAlerts(found);
      if (found.length === 0) setDismissed(false);
    } catch {}
  }, [state]);

  useEffect(() => {
    check();
    const id = setInterval(check, 60_000);
    return () => clearInterval(id);
  }, [check]);

  if (dismissed || alerts.length === 0) return null;

  const hasCritical = alerts.some((a) => a.type === 'critical');

  return (
    <div
      className={`px-4 py-2 text-sm flex items-center justify-between ${
        hasCritical
          ? 'bg-danger/10 text-danger border-b border-danger/20'
          : 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 border-b border-yellow-500/20'
      }`}
    >
      <div className="flex items-center gap-2 flex-wrap">
        <span className="font-medium">{hasCritical ? 'Quota Critical' : 'Quota Warning'}:</span>
        {alerts.map((a) => (
          <span key={a.name} className="inline-flex items-center gap-1">
            <span className="font-semibold">{a.name}</span>
            <span className="opacity-70">({a.detail})</span>
          </span>
        ))}
      </div>
      <button
        onClick={() => setDismissed(true)}
        className="ml-4 opacity-60 hover:opacity-100 transition-opacity shrink-0"
        title="Dismiss"
      >
        ✕
      </button>
    </div>
  );
}
