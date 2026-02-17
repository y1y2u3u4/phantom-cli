'use client';

import type { UsageKeyData } from '@/lib/types';
import { formatUSD, formatBytes, formatNumber } from '@/lib/utils';
import { Card } from '@/components/ui/Card';

interface UsageByKeyProps {
  byKey: Record<string, UsageKeyData>;
}

export function UsageByKey({ byKey }: UsageByKeyProps) {
  const entries = Object.entries(byKey).sort((a, b) => b[1].estimated_cost_usd - a[1].estimated_cost_usd);
  if (entries.length === 0) return null;

  return (
    <Card noPadding>
      <div className="px-5 py-3 border-b border-border">
        <h3 className="text-sm font-medium text-text-primary">By API Key</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs font-medium text-text-secondary uppercase tracking-wider">
              <th className="px-4 py-2">Key ID</th><th className="px-4 py-2">Connections</th>
              <th className="px-4 py-2">Upload</th><th className="px-4 py-2">Download</th>
              <th className="px-4 py-2">Est. Tokens</th>
              <th className="px-4 py-2 text-right">Est. Cost</th>
            </tr>
          </thead>
          <tbody>
            {entries.map(([id, d]) => (
              <tr key={id} className="border-t border-border">
                <td className="px-4 py-2 font-mono text-xs text-text-primary">{id}</td>
                <td className="px-4 py-2 text-text-secondary">{formatNumber(d.connections)}</td>
                <td className="px-4 py-2 text-text-secondary">{formatBytes(d.bytes_upstream)}</td>
                <td className="px-4 py-2 text-text-secondary">{formatBytes(d.bytes_downstream)}</td>
                <td className="px-4 py-2 text-text-secondary">
                  {formatNumber(d.estimated_tokens_in)} in / {formatNumber(d.estimated_tokens_out)} out
                </td>
                <td className="px-4 py-2 text-right font-medium text-text-primary">{formatUSD(d.estimated_cost_usd)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
