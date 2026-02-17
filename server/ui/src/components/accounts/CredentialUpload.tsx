'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import { Dialog } from '@/components/ui/Dialog';
import { Button } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Alert';

interface CredentialUploadProps {
  open: boolean;
  onClose: () => void;
  accountId: string;
  onUploaded: () => void;
}

const CRED_FILES = [
  { key: '.claude/.credentials.json', label: '.claude/.credentials.json' },
  { key: '.claude.json', label: '.claude.json' },
  { key: '.claude/settings.json', label: '.claude/settings.json' },
];

export function CredentialUpload({ open, onClose, accountId, onUploaded }: CredentialUploadProps) {
  const [files, setFiles] = useState<Record<string, string>>({});
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(''); setSuccess('');
    const nonEmpty = Object.fromEntries(Object.entries(files).filter(([, v]) => v.trim()));
    if (Object.keys(nonEmpty).length === 0) { setError('Paste at least one credential file.'); return; }

    setLoading(true);
    try {
      const res = await api.uploadCredentials(accountId, nonEmpty);
      setSuccess(res.message);
      onUploaded();
      setTimeout(onClose, 1500);
    } catch (err: any) {
      setError(err.message || 'Upload failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} title="Upload Credentials">
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && <Alert type="error" message={error} />}
        {success && <Alert type="success" message={success} />}
        <p className="text-xs text-text-secondary">
          Paste the JSON content of each credential file below. Only non-empty fields will be uploaded.
        </p>
        {CRED_FILES.map((f) => (
          <div key={f.key}>
            <label className="block text-xs font-medium text-text-secondary mb-1">{f.label}</label>
            <textarea
              className="w-full h-24 px-3 py-2 text-xs font-mono bg-[var(--input-bg)] border border-[var(--input-border)] rounded-lg text-text-primary focus:outline-none focus:ring-2 focus:ring-accent/50 resize-y"
              placeholder={`Paste ${f.label} content here...`}
              value={files[f.key] || ''}
              onChange={(e) => setFiles({ ...files, [f.key]: e.target.value })}
            />
          </div>
        ))}
        <div className="flex justify-end gap-2 pt-2">
          <Button variant="ghost" type="button" onClick={onClose}>Cancel</Button>
          <Button type="submit" loading={loading}>Upload</Button>
        </div>
      </form>
    </Dialog>
  );
}
