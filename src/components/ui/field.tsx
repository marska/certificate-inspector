'use client';

import type { ReactNode } from 'react';

import { cn, matchesQuery } from '@/lib/utils';
import { CopyButton } from './copy';

export interface FieldSpec {
  label: string;
  value: string;
  /** Render the value in monospace. Defaults to true — most values are technical. */
  mono?: boolean;
  /** Show a copy button. Defaults to true when there is a value. */
  copy?: boolean;
  /** Preserve line breaks in the value. */
  multiline?: boolean;
  /** Extra searchable words that are not shown, e.g. aliases. */
  terms?: string[];
  /** Small note under the value. */
  hint?: string;
  tone?: 'default' | 'success' | 'warning' | 'danger' | 'muted';
}

const toneClass: Record<NonNullable<FieldSpec['tone']>, string> = {
  default: 'text-text',
  success: 'text-success',
  warning: 'text-warning',
  danger: 'text-danger',
  muted: 'text-muted',
};

/** Splits a value so the part matching the search box can be highlighted. */
export function highlight(text: string, query: string): ReactNode {
  const needle = query.trim();
  if (!needle) return text;

  const lower = text.toLowerCase();
  const target = needle.toLowerCase();
  const parts: ReactNode[] = [];
  let cursor = 0;
  let index = lower.indexOf(target);
  let key = 0;

  while (index !== -1 && key < 200) {
    if (index > cursor) parts.push(text.slice(cursor, index));
    parts.push(<mark key={key++}>{text.slice(index, index + target.length)}</mark>);
    cursor = index + target.length;
    index = lower.indexOf(target, cursor);
  }
  if (cursor === 0) return text;
  parts.push(text.slice(cursor));
  return parts;
}

export function Field({
  field,
  query = '',
  className,
}: {
  field: FieldSpec;
  query?: string;
  className?: string;
}) {
  const {
    label,
    value,
    mono = true,
    copy = true,
    multiline = false,
    hint,
    tone = 'default',
  } = field;

  return (
    <div
      className={cn(
        'group grid gap-x-4 gap-y-0.5 px-4 py-2.5 sm:grid-cols-[minmax(9rem,13rem)_1fr]',
        className,
      )}
    >
      <dt className="pt-px text-[12px] leading-5 text-muted">
        {highlight(label, query)}
      </dt>
      <dd className="flex min-w-0 items-start gap-1.5">
        <span
          className={cn(
            'min-w-0 flex-1 text-[13px] leading-5 break-words',
            mono && 'font-mono text-[12.5px]',
            multiline && 'whitespace-pre-line',
            toneClass[tone],
          )}
        >
          {value ? highlight(value, query) : <span className="text-subtle">—</span>}
        </span>
        {copy && value ? (
          <CopyButton
            value={value}
            what={label}
            className="opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100"
          />
        ) : null}
      </dd>
      {hint ? (
        <p className="text-[11px] text-subtle sm:col-start-2">{hint}</p>
      ) : null}
    </div>
  );
}

/**
 * Renders exactly the fields it is given — filtering is the caller's job,
 * because a panel whose *title* matches the search should still show all of
 * its fields. `query` is used only to highlight matches.
 */
export function FieldList({
  fields,
  query = '',
  className,
}: {
  fields: FieldSpec[];
  query?: string;
  className?: string;
}) {
  if (fields.length === 0) return null;

  return (
    <dl className={cn('divide-y divide-line', className)}>
      {fields.map((field) => (
        <Field key={field.label} field={field} query={query} />
      ))}
    </dl>
  );
}

export function filterFields(fields: FieldSpec[], query: string): FieldSpec[] {
  if (!query.trim()) return fields;
  return fields.filter((field) =>
    matchesQuery(query, field.label, field.value, field.hint, ...(field.terms ?? [])),
  );
}
