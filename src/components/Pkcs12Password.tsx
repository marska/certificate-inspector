'use client';

import { useId, useState } from 'react';

import { Button } from '@/components/ui/primitives';
import { cn } from '@/lib/utils';

export interface Pkcs12PasswordProps {
  onSubmit: (password: string) => void;
  /** True while the last submitted password is being tried. */
  busy: boolean;
}

/**
 * Password field for a PKCS#12 / PFX container. Deliberately not a <form>, so
 * password managers do not offer to save it; the value lives only in React
 * state and is dropped when the input changes.
 */
export function Pkcs12Password({ onSubmit, busy }: Pkcs12PasswordProps) {
  const [draft, setDraft] = useState('');
  const inputId = useId();

  const submit = () => {
    if (!busy) onSubmit(draft);
  };

  return (
    <div
      className="flex flex-wrap items-center gap-2 rounded-lg border border-line bg-surface px-3.5 py-2.5"
      style={{ boxShadow: 'var(--shadow)' }}
    >
      <label htmlFor={inputId} className="text-[13px] font-medium text-text">
        PFX password
      </label>
      <input
        id={inputId}
        type="password"
        value={draft}
        autoFocus
        autoComplete="off"
        spellCheck={false}
        data-1p-ignore
        data-lpignore="true"
        data-bwignore
        onChange={(event) => setDraft(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === 'Enter') submit();
        }}
        className={cn(
          'h-8 min-w-[12rem] flex-1 rounded-md border border-line bg-surface px-2.5 sm:max-w-xs',
          'font-mono text-[12.5px] text-text',
          'outline-none focus:border-accent-border focus:ring-2 focus:ring-accent/25',
        )}
      />
      <Button variant="primary" onClick={submit} disabled={busy}>
        {busy ? 'Checking…' : 'Unlock'}
      </Button>
      <span className="text-[11.5px] text-subtle">
        Used only in this tab to decrypt the file — never stored or sent.
      </span>
    </div>
  );
}
