'use client';

import { useTheme } from '@/contexts/ThemeContext';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/Button';

export function Header() {
  const { theme, toggle } = useTheme();
  const { state, role, username, logout } = useAuth();

  return (
    <header className="h-14 border-b border-border bg-card flex items-center justify-between px-5">
      <div className="flex items-center gap-3">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-accent">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <h1 className="text-base font-semibold text-text-primary tracking-tight">
          Phantom
        </h1>
        <span className="text-xs text-text-secondary bg-border/50 px-2 py-0.5 rounded-full">
          Management Console
        </span>
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={toggle}
          className="p-2 text-text-secondary hover:text-text-primary transition-colors rounded-lg hover:bg-border/30"
          aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {theme === 'dark' ? '\u2600\uFE0F' : '\uD83C\uDF19'}
        </button>
        {state === 'authenticated' && (
          <div className="flex items-center gap-2">
            <span className="text-sm text-text-secondary">
              {username || 'Admin'}
            </span>
            {role === 'member' && (
              <span className="text-xs bg-accent/10 text-accent px-1.5 py-0.5 rounded">
                Member
              </span>
            )}
            <Button variant="ghost" size="sm" onClick={logout}>
              Logout
            </Button>
          </div>
        )}
      </div>
    </header>
  );
}
