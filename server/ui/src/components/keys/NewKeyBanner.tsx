'use client';

import { CopyButton } from '@/components/ui/CopyButton';
import { Button } from '@/components/ui/Button';

interface NewKeyBannerProps {
  keyValue: string;
  onDismiss: () => void;
}

export function NewKeyBanner({ keyValue, onDismiss }: NewKeyBannerProps) {
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
    </div>
  );
}
