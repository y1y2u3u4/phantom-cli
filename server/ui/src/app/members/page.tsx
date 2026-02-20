'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import type { Member, Invite } from '@/lib/types';
import { InviteSection } from '@/components/members/InviteSection';
import { MembersTable } from '@/components/members/MembersTable';

export default function MembersPage() {
  const { isAdmin } = useAuth();
  const router = useRouter();
  const [members, setMembers] = useState<Member[] | null>(null);
  const [invites, setInvites] = useState<Invite[] | null>(null);

  useEffect(() => {
    if (!isAdmin) router.replace('/keys');
  }, [isAdmin, router]);

  const refreshMembers = useCallback(async () => {
    try {
      const res = await api.listMembers();
      setMembers(res.members);
    } catch {}
  }, []);

  const refreshInvites = useCallback(async () => {
    try {
      const res = await api.listInvites();
      setInvites(res.invites);
    } catch {}
  }, []);

  useEffect(() => {
    if (isAdmin) {
      refreshMembers();
      refreshInvites();
    }
  }, [isAdmin, refreshMembers, refreshInvites]);

  if (!isAdmin) return null;

  return (
    <div className="max-w-6xl space-y-6">
      <h2 className="text-xl font-semibold text-text-primary">Team Members</h2>

      <InviteSection invites={invites} onRefresh={refreshInvites} />

      <h3 className="text-base font-semibold text-text-primary pt-2">Members</h3>
      <MembersTable members={members} onRefresh={refreshMembers} />
    </div>
  );
}
