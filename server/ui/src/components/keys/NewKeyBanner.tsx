'use client';

import { useState, useEffect } from 'react';
import { api } from '@/lib/api';
import { CopyButton } from '@/components/ui/CopyButton';
import { Button } from '@/components/ui/Button';

interface NewKeyBannerProps {
  keyValue: string;
  onDismiss: () => void;
}

function getServerHost(): string {
  if (typeof window === 'undefined') return 'YOUR_VPS_IP';
  return window.location.hostname;
}

export function NewKeyBanner({ keyValue, onDismiss }: NewKeyBannerProps) {
  const [showGuide, setShowGuide] = useState(true);
  const [sshPassword, setSshPassword] = useState('');
  const host = getServerHost();

  useEffect(() => {
    api.getInstallSettings().then((res) => {
      setSshPassword(res.ssh_password || '');
    }).catch(() => {});
  }, []);

  const installCmd = sshPassword
    ? `curl -fsSL https://raw.githubusercontent.com/y1y2u3u4/phantom-cli/master/client/install.sh | bash -s -- ${host} --key ${keyValue} --ssh-password ${sshPassword}`
    : `curl -fsSL https://raw.githubusercontent.com/y1y2u3u4/phantom-cli/master/client/install.sh | bash -s -- ${host} --key ${keyValue}`;

  return (
    <div className="bg-success/10 border border-success/25 rounded-xl p-4 space-y-3">
      <div className="flex items-center gap-2">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="text-success shrink-0">
          <polyline points="20 6 9 17 4 12"/>
        </svg>
        <span className="text-sm font-medium text-success">API key created successfully</span>
      </div>
      <div className="flex items-center gap-2 bg-[var(--bg)] rounded-lg px-3 py-2">
        <code className="flex-1 text-sm text-text-primary font-mono break-all select-all">
          {keyValue}
        </code>
        <CopyButton text={keyValue} />
      </div>
      <div className="flex items-center justify-between">
        <p className="text-xs text-yellow-500 flex items-center gap-1.5">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          Make sure to copy your API key now. You won&apos;t be able to see it again!
        </p>
        <Button variant="ghost" size="sm" onClick={onDismiss}>Done</Button>
      </div>

      {/* Quick Setup Guide */}
      {showGuide && (
        <div className="mt-2 border-t border-success/15 pt-3 space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-medium text-text-primary flex items-center gap-1.5">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-accent">
                <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
              </svg>
              Quick Setup — Install on your machine
            </h4>
            <button onClick={() => setShowGuide(false)} className="text-text-tertiary hover:text-text-secondary">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
              </svg>
            </button>
          </div>

          <p className="text-xs text-text-secondary">
            Run this command in your terminal to install Phantom CLI and connect to this server:
          </p>

          <div className="bg-[var(--bg)] rounded-lg px-3 py-2.5 space-y-2">
            <code className="block text-xs text-text-primary font-mono break-all select-all leading-relaxed pr-1">
              {installCmd}
            </code>
            <div className="flex justify-end border-t border-border-primary/30 pt-1.5">
              <CopyButton text={installCmd} />
            </div>
          </div>

          <div className="text-xs text-text-secondary space-y-1.5">
            <p className="font-medium text-text-primary">After installation:</p>
            <div className="flex items-start gap-2">
              <span className="inline-flex items-center justify-center w-4 h-4 rounded-full bg-accent/15 text-accent text-[10px] font-bold shrink-0 mt-0.5">1</span>
              <span>Run <code className="px-1 py-0.5 bg-[var(--bg)] rounded text-text-primary font-mono">phantom</code> to start Claude in interactive mode</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="inline-flex items-center justify-center w-4 h-4 rounded-full bg-accent/15 text-accent text-[10px] font-bold shrink-0 mt-0.5">2</span>
              <span>Run <code className="px-1 py-0.5 bg-[var(--bg)] rounded text-text-primary font-mono">phantom -p &quot;hello&quot;</code> for a single query</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="inline-flex items-center justify-center w-4 h-4 rounded-full bg-accent/15 text-accent text-[10px] font-bold shrink-0 mt-0.5">3</span>
              <span>Run <code className="px-1 py-0.5 bg-[var(--bg)] rounded text-text-primary font-mono">phantom doctor</code> to check your connection</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
