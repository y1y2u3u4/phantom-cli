'use client';

import type { UsageResponse } from '@/lib/types';
import { formatBytes, formatNumber } from '@/lib/utils';
import { Card } from '@/components/ui/Card';

interface UsageSummaryProps {
  data: UsageResponse;
}

export function UsageSummary({ data }: UsageSummaryProps) {
  const byKey = data.by_key;
  let totalConn = 0, totalUp = 0, totalDown = 0;
  const activeKeys = new Set<string>();

  for (const [keyId, kd] of Object.entries(byKey)) {
    totalConn += kd.connections;
    totalUp += kd.bytes_upstream;
    totalDown += kd.bytes_downstream;
    if (kd.connections > 0) activeKeys.add(keyId);
  }

  const stats = [
    { label: 'Total Connections', value: formatNumber(totalConn), icon: '\u{1F517}' },
    { label: 'Data Transferred', value: formatBytes(totalUp + totalDown), icon: '\u{1F4E1}' },
    { label: 'Active Keys', value: activeKeys.size.toString(), icon: '\u{1F511}' },
    { label: 'Upload / Download', value: `${formatBytes(totalUp)} / ${formatBytes(totalDown)}`, icon: '\u{1F4CA}' },
  ];

  return (
    <div className="space-y-3">
      <p className="text-xs text-text-secondary">Local proxy statistics (not Anthropic billing). For real quota, see Accounts page.</p>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((s) => (
          <Card key={s.label} className="text-center">
            <div className="text-2xl mb-1">{s.icon}</div>
            <div className="text-lg font-semibold text-text-primary">{s.value}</div>
            <div className="text-xs text-text-secondary">{s.label}</div>
          </Card>
        ))}
      </div>
    </div>
  );
}
