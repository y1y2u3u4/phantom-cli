'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import type { Invite } from '@/lib/types';
import { formatDate } from '@/lib/utils';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Alert } from '@/components/ui/Alert';
import { Badge } from '@/components/ui/Badge';
import { CopyButton } from '@/components/ui/CopyButton';
import { Skeleton } from '@/components/ui/Skeleton';

interface InviteSectionProps {
  invites: Invite[] | null;
  onRefresh: () => void;
}

export function InviteSection({ invites, onRefresh }: InviteSectionProps) {
  const [maxUses, setMaxUses] = useState('10');
  const [creating, setCreating] = useState(false);
  const [newInviteUrl, setNewInviteUrl] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [revoking, setRevoking] = useState<string | null>(null);

  const handleCreate = async () => {
    setError('');
    setCreating(true);
    try {
      const result = await api.createInvite({
        max_uses: parseInt(maxUses) || 10,
      });
      setNewInviteUrl(result.invite_url);
      onRefresh();
    } catch (err: any) {
      setError(err.message || 'Failed to create invite.');
    } finally {
      setCreating(false);
    }
  };

  const handleRevoke = async (token: string) => {
    setRevoking(token);
    try {
      await api.deleteInvite(token);
      onRefresh();
    } catch {} finally {
      setRevoking(null);
    }
  };

  return (
    <div className="space-y-4">
      <Card>
        <h3 className="text-sm font-semibold text-text-primary mb-3">Generate Invite Link</h3>
        {error && <Alert type="error" message={error} />}
        <div className="flex gap-3 items-end">
          <div className="w-32">
            <Input
              label="Max uses"
              type="number"
              value={maxUses}
              onChange={(e) => setMaxUses(e.target.value)}
              min={1}
            />
          </div>
          <Button onClick={handleCreate} loading={creating} loadingText="Creating...">
            Generate Link
          </Button>
        </div>
        {newInviteUrl && (
          <div className="mt-3 p-3 bg-success/10 border border-success/25 rounded-lg">
            <p className="text-xs text-text-secondary mb-1">Share this link with team members:</p>
            <div className="flex items-center gap-2">
              <code className="text-sm text-text-primary font-mono flex-1 break-all">{newInviteUrl}</code>
              <CopyButton text={newInviteUrl} />
            </div>
          </div>
        )}
      </Card>

      {invites === null ? (
        <Card noPadding>
          <div className="p-5 space-y-3">
            {[1, 2].map((i) => (
              <Skeleton key={i} className="h-8 w-full" />
            ))}
          </div>
        </Card>
      ) : invites.length > 0 ? (
        <Card noPadding>
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="bg-border/20">
                  <th className="px-4 py-3 text-xs font-medium text-text-secondary uppercase tracking-wider">Token</th>
                  <th className="px-4 py-3 text-xs font-medium text-text-secondary uppercase tracking-wider">Status</th>
                  <th className="px-4 py-3 text-xs font-medium text-text-secondary uppercase tracking-wider">Uses</th>
                  <th className="px-4 py-3 text-xs font-medium text-text-secondary uppercase tracking-wider">Expires</th>
                  <th className="px-4 py-3 text-xs font-medium text-text-secondary uppercase tracking-wider text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {invites.map((inv) => (
                  <tr key={inv.token} className="border-t border-border hover:bg-border/20 transition-colors">
                    <td className="px-4 py-3">
                      <code className="text-xs text-text-secondary font-mono">
                        {inv.token.length > 16 ? `${inv.token.slice(0, 16)}...` : inv.token}
                      </code>
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant={inv.status === 'active' ? 'active' : inv.status === 'expired' ? 'disabled' : 'exhausted'}>
                        {inv.status}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 text-sm text-text-secondary">
                      {inv.use_count} / {inv.max_uses}
                    </td>
                    <td className="px-4 py-3 text-xs text-text-secondary">
                      {formatDate(inv.expires_at)}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {inv.status === 'active' && (
                        <Button
                          variant="danger"
                          size="sm"
                          loading={revoking === inv.token}
                          onClick={() => handleRevoke(inv.token)}
                        >
                          Revoke
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      ) : null}
    </div>
  );
}
