'use client';

import { classNames } from '@/lib/utils';

interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  options: { value: string; label: string }[];
}

export function Select({ label, options, className, id, ...props }: SelectProps) {
  const selectId = id || label?.toLowerCase().replace(/\s+/g, '-');

  return (
    <div className="space-y-1.5">
      {label && (
        <label htmlFor={selectId} className="block text-xs font-medium text-text-secondary">
          {label}
        </label>
      )}
      <select
        id={selectId}
        className={classNames(
          'w-full px-3 py-2 text-sm bg-[var(--input-bg)] border border-[var(--input-border)] rounded-lg',
          'text-text-primary',
          'focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent',
          'transition-colors appearance-none cursor-pointer',
          className,
        )}
        {...props}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}
