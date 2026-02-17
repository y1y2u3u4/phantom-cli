'use client';

import { useEffect, useState, useCallback } from 'react';
import { api } from '@/lib/api';
import type { UsageResponse } from '@/lib/types';
import { Spinner } from '@/components/ui/Spinner';
import { MonthSelector } from '@/components/usage/MonthSelector';
import { UsageSummary } from '@/components/usage/UsageSummary';
import { UsageChart } from '@/components/usage/UsageChart';
import { UsageByAccount } from '@/components/usage/UsageByAccount';
import { UsageByKey } from '@/components/usage/UsageByKey';

export default function UsagePage() {
  const [data, setData] = useState<UsageResponse | null>(null);
  const [month, setMonth] = useState('');
  const [loading, setLoading] = useState(true);

  const load = useCallback(async (m?: string) => {
    setLoading(true);
    try {
      const res = await api.getUsage(m);
      setData(res);
      if (!m) setMonth(res.month);
    } catch {} finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleMonthChange = (m: string) => { setMonth(m); load(m); };

  if (loading && !data) {
    return (
      <div className="flex items-center justify-center py-20">
        <Spinner size={32} />
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className="max-w-6xl space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-text-primary">Usage</h2>
        <MonthSelector months={data.available_months} selected={month} onChange={handleMonthChange} />
      </div>

      <UsageSummary data={data} />
      <UsageChart byAccount={data.by_account} />
      <UsageByAccount byAccount={data.by_account} />
      <UsageByKey byKey={data.by_key} />
    </div>
  );
}
