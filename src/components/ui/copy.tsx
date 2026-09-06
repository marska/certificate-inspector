'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

import { cn } from '@/lib/utils';
import { Button, type ButtonProps } from './primitives';

/** Copies text and reports a short-lived "Copied" state. */
export function useCopy(resetAfter = 1400) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => () => clearTimeout(timer.current), []);

  const copy = useCallback(
    async (text: string) => {
      try {
        if (navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(text);
        } else {
          // Fallback for non-secure contexts, where the async API is unavailable.
          const area = document.createElement('textarea');
          area.value = text;
          area.setAttribute('readonly', '');
          area.style.position = 'fixed';
          area.style.opacity = '0';
          document.body.appendChild(area);
          area.select();
          document.execCommand('copy');
          document.body.removeChild(area);
        }
        setCopied(true);
        clearTimeout(timer.current);
        timer.current = setTimeout(() => setCopied(false), resetAfter);
      } catch {
        setCopied(false);
      }
    },
    [resetAfter],
  );

  return { copied, copy };
}

export interface CopyButtonProps extends Omit<ButtonProps, 'value' | 'children'> {
  value: string;
  /** Shown next to the icon; omit for an icon-only button. */
  label?: string;
  /** Describes what is copied, for screen readers. */
  what?: string;
}

export function CopyButton({
  value,
  label,
  what,
  className,
  variant = 'ghost',
  size = 'xs',
  ...props
}: CopyButtonProps) {
  const { copied, copy } = useCopy();

  return (
    <Button
      variant={variant}
      size={size}
      aria-label={copied ? 'Copied' : `Copy${what ? ` ${what}` : ''}`}
      title={copied ? 'Copied' : `Copy${what ? ` ${what}` : ''}`}
      onClick={() => copy(value)}
      className={cn(copied && 'text-success', className)}
      {...props}
    >
      <CopyGlyph copied={copied} />
      {label ? <span>{copied ? 'Copied' : label}</span> : null}
      {!label && copied ? <span className="sr-only">Copied</span> : null}
    </Button>
  );
}

function CopyGlyph({ copied }: { copied: boolean }) {
  return copied ? (
    <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" aria-hidden fill="none">
      <path
        d="M3.5 8.5 6.5 11.5 12.5 5"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  ) : (
    <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" aria-hidden fill="none">
      <rect
        x="5.75"
        y="5.75"
        width="7.5"
        height="7.5"
        rx="1.5"
        stroke="currentColor"
        strokeWidth="1.3"
      />
      <path
        d="M10.25 3.75a1.5 1.5 0 0 0-1.5-1.5h-4.5a2 2 0 0 0-2 2v4.5a1.5 1.5 0 0 0 1.5 1.5"
        stroke="currentColor"
        strokeWidth="1.3"
        strokeLinecap="round"
      />
    </svg>
  );
}
