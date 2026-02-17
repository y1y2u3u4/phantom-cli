'use client';

import type { ApiKey, Account } from '@/lib/types';
import { KeyRow } from './KeyRow';
import { Skeleton } from '@/components/ui/Skeleton';

interface KeysTableProps {
  keys: ApiKey[] | null;
  accounts: Account[];
  onRefresh: () => void;
}

export function KeysTable({ keys, accounts, onRefresh }: KeysTableProps) {
  if (keys === null) {
    return (
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="text-left text-xs font-medium text-text-secondary uppercase tracking-wider">
              <th className="px-4 py-3">Name</th><th className="px-4 py-3">Key</th>
              <th className="px-4 py-3">Account</th><th className="px-4 py-3">Created</th>
              <th className="px-4 py-3">Last Used</th><th className="px-4 py-3">Usage</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {[1,2,3].map((i) => (
              <tr key={i} className="border-t border-border">
                <td className="px-4 py-3"><Skeleton className="h-4 w-24"/></td>
                <td className="px-4 py-3"><Skeleton className="h-4 w-40"/></td>
                <td className="px-4 py-3"><Skeleton className="h-4 w-16"/></td>
                <td className="px-4 py-3"><Skeleton className="h-4 w-20"/></td>
                <td className="px-4 py-3"><Skeleton className="h-4 w-20"/></td>
                <td className="px-4 py-3"><Skeleton className="h-4 w-24"/></td>
                <td className="px-4 py-3"><Skeleton className="h-4 w-20 ml-auto"/></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  if (keys.length === 0) {
    return (
      <div className="bg-card border border-border rounded-xl p-12 text-center">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="mx-auto text-text-secondary/50 mb-3">
          <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
        </svg>
        <p className="text-sm text-text-secondary">No API keys yet. Create one above to get started.</p>
      </div>
    );
  }

  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden">
      <table className="w-full">
        <thead>
          <tr className="text-left text-xs font-medium text-text-secondary uppercase tracking-wider">
            <th className="px-4 py-3">Name</th><th className="px-4 py-3">Key</th>
            <th className="px-4 py-3">Account</th><th className="px-4 py-3">Created</th>
            <th className="px-4 py-3">Last Used</th><th className="px-4 py-3">Usage</th>
            <th className="px-4 py-3 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {keys.map((k) => (
            <KeyRow key={k.id} keyData={k} accounts={accounts} onRefresh={onRefresh} />
          ))}
        </tbody>
      </table>
    </div>
  );
}
