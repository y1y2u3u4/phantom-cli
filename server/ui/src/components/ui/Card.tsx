import { classNames } from '@/lib/utils';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  noPadding?: boolean;
}

export function Card({ children, className, noPadding }: CardProps) {
  return (
    <div
      className={classNames(
        'bg-card border border-border rounded-xl shadow-[var(--shadow-sm)]',
        !noPadding && 'p-5',
        className,
      )}
    >
      {children}
    </div>
  );
}
