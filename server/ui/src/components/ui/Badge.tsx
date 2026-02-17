import { classNames } from '@/lib/utils';

interface BadgeProps {
  variant: 'active' | 'exhausted' | 'disabled' | 'info';
  children: React.ReactNode;
}

export function Badge({ variant, children }: BadgeProps) {
  const colors = {
    active: 'bg-success/15 text-success border-success/25',
    exhausted: 'bg-yellow-500/15 text-yellow-500 border-yellow-500/25',
    disabled: 'bg-text-secondary/15 text-text-secondary border-text-secondary/25',
    info: 'bg-accent/15 text-accent border-accent/25',
  };

  return (
    <span
      className={classNames(
        'inline-flex items-center px-2 py-0.5 text-xs font-medium rounded-full border',
        colors[variant],
      )}
    >
      {children}
    </span>
  );
}
