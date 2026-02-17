'use client';

interface MonthSelectorProps {
  months: string[];
  selected: string;
  onChange: (m: string) => void;
}

function formatMonth(m: string): string {
  const [year, month] = m.split('-');
  const names = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  return `${names[parseInt(month) - 1] || month} ${year}`;
}

export function MonthSelector({ months, selected, onChange }: MonthSelectorProps) {
  if (months.length === 0) return null;

  return (
    <select
      value={selected}
      onChange={(e) => onChange(e.target.value)}
      className="px-3 py-2 text-sm bg-[var(--input-bg)] border border-[var(--input-border)] rounded-lg text-text-primary focus:outline-none focus:ring-2 focus:ring-accent/50"
    >
      {months.map((m) => (
        <option key={m} value={m}>{formatMonth(m)}</option>
      ))}
    </select>
  );
}
