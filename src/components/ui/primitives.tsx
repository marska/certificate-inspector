'use client';

import { cva, type VariantProps } from 'class-variance-authority';
import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from 'react';

import { cn } from '@/lib/utils';

/* ------------------------------------------------------------------ */
/* Button                                                              */
/* ------------------------------------------------------------------ */

const buttonStyles = cva(
  'inline-flex items-center justify-center gap-1.5 rounded-md font-medium ' +
    'whitespace-nowrap transition-colors outline-none select-none ' +
    'focus-visible:ring-2 focus-visible:ring-accent/60 focus-visible:ring-offset-1 ' +
    'focus-visible:ring-offset-canvas disabled:pointer-events-none disabled:opacity-50',
  {
    variants: {
      variant: {
        primary: 'bg-accent text-white hover:opacity-90',
        outline:
          'border border-line bg-surface text-text hover:bg-surface-2 hover:border-line-strong',
        ghost: 'text-muted hover:bg-surface-2 hover:text-text',
        subtle: 'bg-surface-2 text-muted hover:bg-surface-3 hover:text-text',
      },
      size: {
        xs: 'h-6 px-1.5 text-[11px]',
        sm: 'h-7.5 px-2.5 text-xs',
        md: 'h-9 px-3.5 text-sm',
      },
    },
    defaultVariants: { variant: 'outline', size: 'sm' },
  },
);

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonStyles> {}

export function Button({ className, variant, size, ...props }: ButtonProps) {
  return (
    <button
      type="button"
      className={cn(buttonStyles({ variant, size }), className)}
      {...props}
    />
  );
}

/* ------------------------------------------------------------------ */
/* Badge                                                               */
/* ------------------------------------------------------------------ */

const badgeStyles = cva(
  'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 ' +
    'text-[11px] font-medium leading-4 whitespace-nowrap',
  {
    variants: {
      tone: {
        neutral: 'border-line bg-surface-2 text-muted',
        success: 'border-success-border bg-success-soft text-success',
        warning: 'border-warning-border bg-warning-soft text-warning',
        danger: 'border-danger-border bg-danger-soft text-danger',
        info: 'border-info-border bg-info-soft text-info',
        accent: 'border-accent-border bg-accent-soft text-accent',
      },
    },
    defaultVariants: { tone: 'neutral' },
  },
);

export type BadgeTone = NonNullable<VariantProps<typeof badgeStyles>['tone']>;

export interface BadgeProps
  extends HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeStyles> {}

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeStyles({ tone }), className)} {...props} />;
}

/* ------------------------------------------------------------------ */
/* Panel — the section card used throughout the details pane           */
/* ------------------------------------------------------------------ */

export interface PanelProps {
  title: string;
  /** Rendered to the right of the title. */
  aside?: ReactNode;
  description?: string;
  children: ReactNode;
  className?: string;
  id?: string;
}

export function Panel({
  title,
  aside,
  description,
  children,
  className,
  id,
}: PanelProps) {
  return (
    <section
      id={id}
      className={cn(
        'overflow-hidden rounded-lg border border-line bg-surface',
        className,
      )}
      style={{ boxShadow: 'var(--shadow)' }}
    >
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-surface-2/60 px-4 py-2.5">
        <div className="min-w-0">
          <h2 className="text-[13px] font-semibold tracking-tight text-text">{title}</h2>
          {description ? (
            <p className="mt-0.5 text-[11px] text-subtle">{description}</p>
          ) : null}
        </div>
        {aside ? <div className="flex items-center gap-1.5">{aside}</div> : null}
      </header>
      {children}
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Segmented control                                                   */
/* ------------------------------------------------------------------ */

export interface SegmentedProps<T extends string> {
  options: { value: T; label: string }[];
  value: T;
  onChange: (value: T) => void;
  'aria-label'?: string;
  className?: string;
}

export function Segmented<T extends string>({
  options,
  value,
  onChange,
  className,
  ...rest
}: SegmentedProps<T>) {
  return (
    <div
      role="group"
      aria-label={rest['aria-label']}
      className={cn(
        'inline-flex items-center gap-0.5 rounded-md border border-line bg-surface-2 p-0.5',
        className,
      )}
    >
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          aria-pressed={value === option.value}
          onClick={() => onChange(option.value)}
          className={cn(
            'rounded px-2 py-0.5 text-[11px] font-medium transition-colors',
            value === option.value
              ? 'bg-surface text-text shadow-sm'
              : 'text-subtle hover:text-text',
          )}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Status glyphs                                                       */
/* ------------------------------------------------------------------ */

export function Tick({ ok }: { ok: boolean }) {
  return (
    <span
      aria-hidden
      className={cn(
        'inline-flex h-4 w-4 shrink-0 items-center justify-center text-[13px] font-semibold',
        ok ? 'text-success' : 'text-subtle',
      )}
    >
      {ok ? '✓' : '✗'}
    </span>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <p className="px-4 py-3 text-[13px] text-subtle italic">{children}</p>;
}
