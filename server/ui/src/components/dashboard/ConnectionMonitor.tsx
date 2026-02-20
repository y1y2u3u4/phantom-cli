'use client';

import { useEffect, useState, useCallback } from 'react';
import { api } from '@/lib/api';
import type { HealthConnections } from '@/lib/types';
import { Card } from '@/components/ui/Card';
import { Skeleton } from '@/components/ui/Skeleton';

export function ConnectionMonitor() {
  const [data, setData] = useState<HealthConnections | null>(null);
  const [error, setError] = useState('');

  const fetchHealth = useCallback(async () => {
    try {
      const res = await api.getHealth();
      setData(res.connections);
      setError('');
    } catch {
      setError('Failed to fetch health data.');
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    const id = setInterval(fetchHealth, 5000);
    return () => clearInterval(id);
  }, [fetchHealth]);

  if (!data && !error) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-32 w-full" />
        <Skeleton className="h-24 w-full" />
      </div>
    );
  }

  if (error) {
    return (
      <Card className="text-center py-8">
        <p className="text-sm text-danger">{error}</p>
      </Card>
    );
  }

  const pct = data!.max > 0 ? Math.round((data!.active / data!.max) * 100) : 0;
  const accounts = Object.entries(data!.per_account);

  return (
    <div className="space-y-4">
      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Total Connections" value={data!.active} max={data!.max} />
        <StatCard label="Active" value={data!.truly_active} accent="text-success" />
        <StatCard label="Idle" value={data!.idle} accent="text-text-secondary" />
        <StatCard label="Capacity" value={`${pct}%`} accent={pct > 80 ? 'text-danger' : 'text-success'} />
      </div>

      {/* Capacity bar */}
      <Card>
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium text-text-secondary">Global Capacity</span>
          <span className="text-xs text-text-secondary">{data!.active} / {data!.max}</span>
        </div>
        <div className="w-full h-3 bg-border/30 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-500 ${pct > 80 ? 'bg-danger' : pct > 50 ? 'bg-yellow-500' : 'bg-success'}`}
            style={{ width: `${Math.min(pct, 100)}%` }}
          />
        </div>
        <p className="text-xs text-text-secondary mt-1.5">Idle timeout: {data!.idle_timeout}s</p>
      </Card>

      {/* Per-account breakdown */}
      {accounts.length > 0 && (
        <Card noPadding>
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="bg-border/20">
                  <th className="px-4 py-3 text-xs font-medium text-text-secondary uppercase tracking-wider">Account</th>
                  <th className="px-4 py-3 text-xs font-medium text-text-secondary uppercase tracking-wider">Total</th>
                  <th className="px-4 py-3 text-xs font-medium text-text-secondary uppercase tracking-wider">Active</th>
                  <th className="px-4 py-3 text-xs font-medium text-text-secondary uppercase tracking-wider">Idle</th>
                  <th className="px-4 py-3 text-xs font-medium text-text-secondary uppercase tracking-wider">Load</th>
                </tr>
              </thead>
              <tbody>
                {accounts.map(([id, acc]) => {
                  const accPct = data!.per_account_max > 0
                    ? Math.round((acc.total / data!.per_account_max) * 100)
                    : 0;
                  return (
                    <tr key={id} className="border-t border-border hover:bg-border/20 transition-colors">
                      <td className="px-4 py-3 text-sm font-medium text-text-primary">{acc.name}</td>
                      <td className="px-4 py-3 text-sm text-text-secondary">{acc.total}</td>
                      <td className="px-4 py-3 text-sm text-success">{acc.active}</td>
                      <td className="px-4 py-3 text-sm text-text-secondary">{acc.idle}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-2 bg-border/30 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${accPct > 80 ? 'bg-danger' : 'bg-accent'}`}
                              style={{ width: `${Math.min(accPct, 100)}%` }}
                            />
                          </div>
                          <span className="text-xs text-text-secondary">{accPct}%</span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}

function StatCard({ label, value, max, accent }: {
  label: string;
  value: number | string;
  max?: number;
  accent?: string;
}) {
  return (
    <Card className="text-center py-3">
      <p className={`text-2xl font-bold ${accent || 'text-text-primary'}`}>
        {value}
        {max !== undefined && (
          <span className="text-sm font-normal text-text-secondary"> / {max}</span>
        )}
      </p>
      <p className="text-xs text-text-secondary mt-0.5">{label}</p>
    </Card>
  );
}
