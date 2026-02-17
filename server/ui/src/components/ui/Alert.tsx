'use client';

import { classNames } from '@/lib/utils';

interface AlertProps {
  type: 'error' | 'success';
  message: string;
  className?: string;
}

export function Alert({ type, message, className }: AlertProps) {
  if (!message) return null;

  return (
    <div
      className={classNames(
        'flex items-center gap-2 px-3 py-2 text-sm rounded-lg border',
        type === 'error' && 'bg-danger/10 border-danger/25 text-danger',
        type === 'success' && 'bg-success/10 border-success/25 text-success',
        className,
      )}
      role="alert"
    >
      {type === 'error' ? (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="shrink-0">
          <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
        </svg>
      ) : (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="shrink-0">
          <polyline points="20 6 9 17 4 12"/>
        </svg>
      )}
      <span>{message}</span>
    </div>
  );
}
