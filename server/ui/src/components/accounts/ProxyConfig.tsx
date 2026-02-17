'use client';

import type { UpstreamProxyInput } from '@/lib/types';
import { Input } from '@/components/ui/Input';

interface ProxyConfigProps {
  value: UpstreamProxyInput;
  onChange: (v: UpstreamProxyInput) => void;
}

export function ProxyConfig({ value, onChange }: ProxyConfigProps) {
  const update = (fields: Partial<UpstreamProxyInput>) => onChange({ ...value, ...fields });

  return (
    <div className="space-y-3">
      <div>
        <label className="block text-xs font-medium text-text-secondary mb-1.5">Proxy type</label>
        <select
          value={value.type}
          onChange={(e) => update({ type: e.target.value as any })}
          className="w-full px-3 py-2 text-sm bg-[var(--input-bg)] border border-[var(--input-border)] rounded-lg text-text-primary focus:outline-none focus:ring-2 focus:ring-accent/50"
        >
          <option value="direct">Direct (no upstream proxy)</option>
          <option value="http">HTTP CONNECT proxy</option>
          <option value="socks5">SOCKS5 proxy</option>
        </select>
      </div>
      {value.type !== 'direct' && (
        <>
          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2">
              <Input label="Host" value={value.host || ''} onChange={(e) => update({ host: e.target.value })} placeholder="proxy.example.com" />
            </div>
            <Input label="Port" type="number" value={value.port?.toString() || ''} onChange={(e) => update({ port: parseInt(e.target.value) || 0 })} placeholder="8080" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Input label="Username (optional)" value={value.username || ''} onChange={(e) => update({ username: e.target.value })} placeholder="user" />
            <Input label="Password (optional)" type="password" value={value.password || ''} onChange={(e) => update({ password: e.target.value })} placeholder="pass" />
          </div>
        </>
      )}
    </div>
  );
}
