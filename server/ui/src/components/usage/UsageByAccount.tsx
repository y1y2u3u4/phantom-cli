'use client';

import type { UsageAccountData } from '@/lib/types';
import { formatUSD, formatBytes, formatNumber } from '@/lib/utils';
import { Card } from '@/components/ui/Card';

interface UsageByAccountProps {
  byAccount: Record<string, UsageAccountData>;
}

export function UsageByAccount({ byAccount }: UsageByAccountProps) {
  const entries = Object.entries(byAccount).sort((a, b) => b[1].estimated_cost_usd - a[1].estimated_cost_usd);
  if (entries.length === 0) return null;

  let totalConn = 0, totalUp = 0, totalDown = 0, totalCost = 0;
  entries.forEach(([, d]) => { totalConn += d.connections; totalUp += d.bytes_upstream; totalDown += d.bytes_downstream; totalCost += d.estimated_cost_usd; });

  return (
    <Card noPadding>
      <div className="px-5 py-3 border-b border-border">
        <h3 className="text-sm font-medium text-text-primary">By Account</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs font-medium text-text-secondary uppercase tracking-wider">
              <th className="px-4 py-2">Account</th><th className="px-4 py-2">Connections</th>
              <th className="px-4 py-2">Upload</th><th className="px-4 py-2">Download</th>
              <th className="px-4 py-2 text-right">Est. Cost</th>
            </tr>
          </thead>
          <tbody>
            {entries.map(([id, d]) => (
              <tr key={id} className="border-t border-border">
                <td className="px-4 py-2 font-medium text-text-primary">{d.account_name || id}</td>
                <td className="px-4 py-2 text-text-secondary">{formatNumber(d.connections)}</td>
                <td className="px-4 py-2 text-text-secondary">{formatBytes(d.bytes_upstream)}</td>
                <td className="px-4 py-2 text-text-secondary">{formatBytes(d.bytes_downstream)}</td>
                <td className="px-4 py-2 text-right font-medium text-text-primary">{formatUSD(d.estimated_cost_usd)}</td>
              </tr>
            ))}
            <tr className="border-t-2 border-border font-semibold">
              <td className="px-4 py-2 text-text-primary">Total</td>
              <td className="px-4 py-2 text-text-primary">{formatNumber(totalConn)}</td>
              <td className="px-4 py-2 text-text-primary">{formatBytes(totalUp)}</td>
              <td className="px-4 py-2 text-text-primary">{formatBytes(totalDown)}</td>
              <td className="px-4 py-2 text-right text-text-primary">{formatUSD(totalCost)}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </Card>
  );
}
