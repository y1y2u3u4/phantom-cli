import { classNames } from '@/lib/utils';

interface SkeletonProps {
  className?: string;
}

export function Skeleton({ className }: SkeletonProps) {
  return (
    <div
      className={classNames(
        'animate-pulse rounded bg-border/50',
        className || 'h-4 w-full',
      )}
    />
  );
}
