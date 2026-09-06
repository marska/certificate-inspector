'use client';

import type { DecodeIssue } from '@/lib/certificate/types';
import { cn } from '@/lib/utils';

const TONE: Record<
  DecodeIssue['severity'],
  { wrapper: string; icon: string; glyph: string }
> = {
  error: {
    wrapper: 'border-danger-border bg-danger-soft',
    icon: 'text-danger',
    glyph: '✕',
  },
  warning: {
    wrapper: 'border-warning-border bg-warning-soft',
    icon: 'text-warning',
    glyph: '!',
  },
  info: { wrapper: 'border-info-border bg-info-soft', icon: 'text-info', glyph: 'i' },
};

/** The unmissable banner for a pasted private key (spec §24). */
export function PrivateKeyAlert() {
  return (
    <div
      role="alert"
      className="rounded-lg border-2 border-danger-border bg-danger-soft px-4 py-3"
    >
      <div className="flex items-start gap-3">
        <span
          aria-hidden
          className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-danger text-[13px] font-bold text-white"
        >
          !
        </span>
        <div className="space-y-1">
          <p className="text-[13px] font-semibold tracking-wide text-danger uppercase">
            Private key detected
          </p>
          <p className="text-[13px] leading-relaxed text-text">
            Do not paste private keys into online tools. This key was{' '}
            <strong className="font-semibold">not uploaded and not stored</strong> — the
            page never sends your input anywhere — but the habit is dangerous. If this key
            is used in production, treat it as compromised and rotate it.
          </p>
        </div>
      </div>
    </div>
  );
}

export function IssueList({
  issues,
  className,
}: {
  issues: DecodeIssue[];
  className?: string;
}) {
  if (issues.length === 0) return null;

  return (
    <div className={cn('space-y-2', className)}>
      {issues.map((issue, index) => {
        const tone = TONE[issue.severity];
        return (
          <div
            key={`${issue.code}-${index}`}
            role={issue.severity === 'error' ? 'alert' : undefined}
            className={cn('rounded-lg border px-3.5 py-2.5', tone.wrapper)}
          >
            <div className="flex items-start gap-2.5">
              <span
                aria-hidden
                className={cn(
                  'mt-px flex h-4 w-4 shrink-0 items-center justify-center rounded-full border text-[10px] font-bold',
                  tone.icon,
                )}
              >
                {tone.glyph}
              </span>
              <div className="min-w-0 space-y-0.5">
                <p className="text-[13px] font-medium text-text">{issue.message}</p>
                {issue.detail ? (
                  <p className="text-[12px] leading-relaxed text-muted">{issue.detail}</p>
                ) : null}
                <p className="pt-0.5 font-mono text-[10px] tracking-wide text-subtle">
                  {issue.code}
                </p>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/** Shown under the input: what the app did and did not do with the data. */
export function PrivacyNote({ className }: { className?: string }) {
  return (
    <p className={cn('text-[11.5px] leading-relaxed text-subtle', className)}>
      <span aria-hidden className="mr-1">
        🔒
      </span>
      Your certificate is parsed locally in your browser. Nothing is uploaded to a server,
      logged, stored, or put in the URL.
    </p>
  );
}
