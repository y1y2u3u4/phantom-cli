'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import { useToast } from '@/contexts/ToastContext';
import type { Member } from '@/lib/types';
import { formatDate } from '@/lib/utils';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';

interface MemberRowProps {
  member: Member;
  onRefresh: () => void;
}

export function MemberRow({ member, onRefresh }: MemberRowProps) {
  const toast = useToast();
  const [toggling, setToggling] = useState(false);

  const handleToggleStatus = async () => {
    setToggling(true);
    try {
      const newStatus = member.status === 'active' ? 'disabled' : 'active';
      await api.updateMember(member.id, { status: newStatus });
      toast.success(`Member ${newStatus === 'active' ? 'enabled' : 'disabled'}.`);
      onRefresh();
    } catch {} finally {
      setToggling(false);
    }
  };

  return (
    <tr className="border-t border-border hover:bg-border/20 transition-colors">
      <td className="px-4 py-3 text-sm font-medium text-text-primary">
        {member.username}
      </td>
      <td className="px-4 py-3">
        <Badge variant={member.role === 'admin' ? 'info' : 'active'}>
          {member.role}
        </Badge>
      </td>
      <td className="px-4 py-3">
        <Badge variant={member.status === 'active' ? 'active' : 'disabled'}>
          {member.status}
        </Badge>
      </td>
      <td className="px-4 py-3 text-sm text-text-secondary">
        {member.key_count}
      </td>
      <td className="px-4 py-3 text-xs text-text-secondary">
        {member.last_login_at ? formatDate(member.last_login_at) : <span className="opacity-50">Never</span>}
      </td>
      <td className="px-4 py-3 text-xs text-text-secondary">
        {member.last_login_ip || '-'}
      </td>
      <td className="px-4 py-3 text-right">
        <Button
          variant={member.status === 'active' ? 'danger' : 'primary'}
          size="sm"
          loading={toggling}
          onClick={handleToggleStatus}
        >
          {member.status === 'active' ? 'Disable' : 'Enable'}
        </Button>
      </td>
    </tr>
  );
}
