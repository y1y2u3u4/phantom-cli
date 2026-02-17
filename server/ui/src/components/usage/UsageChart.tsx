'use client';

import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import type { UsageAccountData } from '@/lib/types';
import { Card } from '@/components/ui/Card';

interface UsageChartProps {
  byAccount: Record<string, UsageAccountData>;
}

const COLORS = ['#6366f1', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4'];

export function UsageChart({ byAccount }: UsageChartProps) {
  const entries = Object.entries(byAccount);
  if (entries.length === 0) {
    return (
      <Card className="p-8 text-center">
        <p className="text-sm text-text-secondary">No usage data to display.</p>
      </Card>
    );
  }

  const chartData = entries.map(([id, d]) => ({
    name: d.account_name || id,
    cost: parseFloat(d.estimated_cost_usd.toFixed(2)),
    connections: d.connections,
  }));

  return (
    <Card>
      <h3 className="text-sm font-medium text-text-primary mb-4">Cost by Account</h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey="name" tick={{ fill: 'var(--text-secondary)', fontSize: 12 }} />
            <YAxis tick={{ fill: 'var(--text-secondary)', fontSize: 12 }} tickFormatter={(v) => `$${v}`} />
            <Tooltip
              contentStyle={{ backgroundColor: 'var(--card-bg)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text-primary)' }}
              formatter={(value: number) => [`$${value.toFixed(2)}`, 'Cost']}
            />
            <Bar dataKey="cost" fill={COLORS[0]} radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
