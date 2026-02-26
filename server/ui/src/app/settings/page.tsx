'use client';

import { useState, useEffect } from 'react';
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/contexts/ToastContext';
import { Card } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';

export default function SettingsPage() {
  const { role, username, isAdmin } = useAuth();
  const toast = useToast();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Site settings (admin only)
  const [sshPassword, setSshPassword] = useState('');
  const [sshPasswordSaved, setSshPasswordSaved] = useState('');
  const [sshLoading, setSshLoading] = useState(false);

  useEffect(() => {
    if (isAdmin) {
      api.getSettings().then((res) => {
        setSshPassword(res.ssh_password || '');
        setSshPasswordSaved(res.ssh_password || '');
      }).catch(() => {});
    }
  }, [isAdmin]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!currentPassword || !newPassword) {
      setError('Please fill in all fields.');
      return;
    }
    if (newPassword.length < 4) {
      setError('New password must be at least 4 characters.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('New passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      await api.changePassword(currentPassword, newPassword);
      toast.success('Password changed successfully.');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: any) {
      setError(err.message || 'Failed to change password.');
    } finally {
      setLoading(false);
    }
  };

  const handleSshSave = async () => {
    setSshLoading(true);
    try {
      await api.updateSettings({ ssh_password: sshPassword });
      setSshPasswordSaved(sshPassword);
      toast.success('SSH password updated.');
    } catch (err: any) {
      toast.error(err.message || 'Failed to update settings.');
    } finally {
      setSshLoading(false);
    }
  };

  return (
    <div className="max-w-xl space-y-6">
      <h2 className="text-xl font-semibold text-text-primary">Settings</h2>

      <Card>
        <h3 className="text-sm font-semibold text-text-primary mb-1">Change Password</h3>
        <p className="text-xs text-text-secondary mb-4">
          {role === 'admin' && !username
            ? 'Update the master admin password.'
            : `Update password for ${username}.`}
        </p>

        {error && <Alert type="error" message={error} />}

        <form onSubmit={handleSubmit} className="space-y-3">
          <Input
            label="Current password"
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            placeholder="Enter current password"
          />
          <Input
            label="New password"
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            placeholder="Enter new password"
          />
          <Input
            label="Confirm new password"
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Confirm new password"
          />
          <div className="pt-1">
            <Button type="submit" loading={loading} loadingText="Changing...">
              Change Password
            </Button>
          </div>
        </form>
      </Card>

      {isAdmin && (
        <Card>
          <h3 className="text-sm font-semibold text-text-primary mb-1">Install Settings</h3>
          <p className="text-xs text-text-secondary mb-4">
            Configure values shown in member install instructions. The SSH password enables tunnel mode for users behind corporate firewalls.
          </p>

          <div className="space-y-3">
            <Input
              label="VPS SSH Password (for tunnel mode)"
              type="text"
              value={sshPassword}
              onChange={(e) => setSshPassword(e.target.value)}
              placeholder="Leave empty to disable tunnel instructions"
            />
            <div className="pt-1">
              <Button
                onClick={handleSshSave}
                loading={sshLoading}
                loadingText="Saving..."
                disabled={sshPassword === sshPasswordSaved}
              >
                Save
              </Button>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
