'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/Button';

interface TestConnectionProps {
  accountId: string;
}

export function TestConnection({ accountId }: TestConnectionProps) {
  const [result, setResult] = useState<{ success: boolean; message: string } | null>(null);
  const [loading, setLoading] = useState(false);

  const test = async () => {
    setResult(null);
    setLoading(true);
    try {
      const res = await api.testAccount(accountId);
      setResult(res);
    } catch (err: any) {
      setResult({ success: false, message: err.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-2">
      <Button variant="ghost" size="sm" onClick={test} loading={loading} loadingText="Testing...">
        Test Connection
      </Button>
      {result && (
        <p className={`text-xs ${result.success ? 'text-success' : 'text-danger'}`}>
          {result.success ? '\u2713' : '\u2717'} {result.message}
        </p>
      )}
    </div>
  );
}
