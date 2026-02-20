'use client';

import type { Member } from '@/lib/types';
import { Card } from '@/components/ui/Card';
import { Skeleton } from '@/components/ui/Skeleton';
import { MemberRow } from './MemberRow';

interface MembersTableProps {
  members: Member[] | null;
  onRefresh: () => void;
}

export function MembersTable({ members, onRefresh }: MembersTableProps) {
  if (members === null) {
    return (
      <Card noPadding>
        <div className="p-5 space-y-3">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </div>
      </Card>
    );
  }

  if (members.length === 0) {
    return (
      <Card className="p-12 text-center">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="mx-auto text-text-secondary/50 mb-3">
          <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/>
          <circle cx="9" cy="7" r="4"/>
          <line x1="19" y1="8" x2="19" y2="14"/>
          <line x1="22" y1="11" x2="16" y2="11"/>
        </svg>
        <p className="text-sm text-text-secondary">No team members yet. Create an invite link to get started.</p>
      </Card>
    );
  }

  return (
    <Card noPadding>
      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead>
            <tr className="bg-border/20">
              <th className="px-4 py-3 text-xs font-medium text-text-secondary uppercase tracking-wider">Username</th>
              <th className="px-4 py-3 text-xs font-medium text-text-secondary uppercase tracking-wider">Role</th>
              <th className="px-4 py-3 text-xs font-medium text-text-secondary uppercase tracking-wider">Status</th>
              <th className="px-4 py-3 text-xs font-medium text-text-secondary uppercase tracking-wider">Keys</th>
              <th className="px-4 py-3 text-xs font-medium text-text-secondary uppercase tracking-wider">Last Login</th>
              <th className="px-4 py-3 text-xs font-medium text-text-secondary uppercase tracking-wider">IP</th>
              <th className="px-4 py-3 text-xs font-medium text-text-secondary uppercase tracking-wider text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {members.map((m) => (
              <MemberRow key={m.id} member={m} onRefresh={onRefresh} />
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
