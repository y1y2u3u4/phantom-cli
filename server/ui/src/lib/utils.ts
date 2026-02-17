export function formatDate(isoString: string | null | undefined): string | null {
  if (!isoString) return null;
  let date: Date;
  try {
    date = new Date(isoString);
  } catch {
    return isoString;
  }
  if (isNaN(date.getTime())) return isoString;

  const now = Date.now();
  const diff = Math.floor((now - date.getTime()) / 1000);

  if (diff < 60) return 'Just now';
  if (diff < 3600) {
    const m = Math.floor(diff / 60);
    return `${m} minute${m !== 1 ? 's' : ''} ago`;
  }
  if (diff < 86400) {
    const h = Math.floor(diff / 3600);
    return `${h} hour${h !== 1 ? 's' : ''} ago`;
  }
  if (diff < 2592000) {
    const d = Math.floor(diff / 86400);
    return `${d} day${d !== 1 ? 's' : ''} ago`;
  }
  if (diff < 31536000) {
    const mo = Math.floor(diff / 2592000);
    return `${mo} month${mo !== 1 ? 's' : ''} ago`;
  }
  const yr = Math.floor(diff / 31536000);
  return `${yr} year${yr !== 1 ? 's' : ''} ago`;
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export function formatUSD(amount: number): string {
  return `$${amount.toFixed(2)}`;
}

export function formatNumber(n: number): string {
  return n.toLocaleString('en-US');
}

export function classNames(...classes: (string | false | null | undefined)[]): string {
  return classes.filter(Boolean).join(' ');
}
