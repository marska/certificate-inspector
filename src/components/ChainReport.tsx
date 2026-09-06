'use client';

import { Panel } from '@/components/ui/primitives';
import type {
  CertificateChain as Chain,
  ChainIssue,
  LinkCheck,
} from '@/lib/certificate/types';
import { cn, matchesQuery } from '@/lib/utils';

const SEVERITY_ORDER: Record<ChainIssue['severity'], number> = {
  error: 0,
  warning: 1,
  info: 2,
  success: 3,
};

const SEVERITY_STYLE: Record<
  ChainIssue['severity'],
  { glyph: string; color: string }
> = {
  error: { glyph: '✕', color: 'text-danger' },
  warning: { glyph: '⚠', color: 'text-warning' },
  info: { glyph: 'ℹ', color: 'text-info' },
  success: { glyph: '✓', color: 'text-success' },
};

const CHECK_STYLE: Record<LinkCheck['status'], { glyph: string; color: string }> = {
  ok: { glyph: '✓', color: 'text-success' },
  fail: { glyph: '✕', color: 'text-danger' },
  unknown: { glyph: '?', color: 'text-warning' },
  skipped: { glyph: '–', color: 'text-subtle' },
};

export function ChainReport({
  chain,
  query = '',
  onSelect,
}: {
  chain: Chain;
  query?: string;
  onSelect?: (id: string) => void;
}) {
  const issues = [...chain.issues].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
  const visibleIssues = issues.filter((issue) =>
    matchesQuery(query, issue.message, issue.detail, issue.code),
  );

  return (
    <div className="space-y-4">
      <Panel
        title="Chain diagnostics"
        description="Everything that can be checked without a trust store."
      >
        {visibleIssues.length === 0 ? (
          <p className="px-4 py-3 text-[13px] text-subtle italic">
            {issues.length === 0
              ? 'No findings.'
              : 'No diagnostics match the current search.'}
          </p>
        ) : (
          <ul className="divide-y divide-line">
            {visibleIssues.map((issue, index) => {
              const style = SEVERITY_STYLE[issue.severity];
              const certificate = chain.certificates.find(
                (candidate) => candidate.id === issue.certificateId,
              );
              return (
                <li
                  key={`${issue.code}-${index}`}
                  className="flex items-start gap-2.5 px-4 py-2.5"
                >
                  <span
                    aria-hidden
                    className={cn('mt-px w-4 shrink-0 text-center text-[13px]', style.color)}
                  >
                    {style.glyph}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="text-[13px] leading-5 text-text">{issue.message}</p>
                    {issue.detail ? (
                      <p className="mt-0.5 text-[12px] leading-relaxed text-muted">
                        {issue.detail}
                      </p>
                    ) : null}
                    <p className="mt-1 flex flex-wrap items-center gap-2 font-mono text-[10px] text-subtle">
                      <span>{issue.code}</span>
                      {certificate && onSelect ? (
                        <button
                          type="button"
                          onClick={() => onSelect(certificate.id)}
                          className="underline decoration-dotted underline-offset-2 hover:text-accent"
                        >
                          {certificate.label}
                        </button>
                      ) : null}
                    </p>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Panel>

      <Panel
        title="Link verification"
        description="Issuer relations and signatures, one hop at a time."
      >
        {chain.links.length === 0 ? (
          <p className="px-4 py-3 text-[13px] text-subtle italic">
            Nothing to verify — no certificates were parsed.
          </p>
        ) : (
          <ul className="divide-y divide-line">
            {chain.links.map((link) => (
              <li key={link.subjectId} className="px-4 py-3">
                <p className="font-mono text-[12px] text-text">
                  <span>{link.subjectLabel}</span>
                  {link.issuerLabel && link.issuerId !== link.subjectId ? (
                    <>
                      <span aria-hidden className="mx-1.5 text-subtle">
                        →
                      </span>
                      <span>{link.issuerLabel}</span>
                    </>
                  ) : (
                    <span className="ml-1.5 text-subtle">(self)</span>
                  )}
                </p>
                <ul className="mt-1.5 space-y-1">
                  {link.checks.map((check) => {
                    const style = CHECK_STYLE[check.status];
                    return (
                      <li key={check.label} className="flex items-start gap-2">
                        <span
                          aria-hidden
                          className={cn('w-4 shrink-0 text-center text-[12px]', style.color)}
                        >
                          {style.glyph}
                        </span>
                        <span className="min-w-0">
                          <span className="text-[12.5px] text-text">{check.label}</span>
                          {check.detail ? (
                            <span className="block font-mono text-[11px] break-words text-subtle">
                              {check.detail}
                            </span>
                          ) : null}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
