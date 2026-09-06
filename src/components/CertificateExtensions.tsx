'use client';

import { CopyButton } from '@/components/ui/copy';
import { Badge, EmptyState, Panel } from '@/components/ui/primitives';
import { highlight } from '@/components/ui/field';
import type { ParsedCertificate } from '@/lib/certificate/types';
import { matchesQuery } from '@/lib/utils';

export function CertificateExtensions({
  certificate,
  query = '',
}: {
  certificate: ParsedCertificate;
  query?: string;
}) {
  const extensions = certificate.extensions.filter((extension) =>
    matchesQuery(query, extension.name, extension.oid, extension.value),
  );
  const criticalCount = certificate.extensions.filter((e) => e.critical).length;

  return (
    <Panel
      title="Extensions"
      description={`Every extension present in the certificate, decoded where possible.`}
      aside={
        <>
          <Badge tone="neutral">{certificate.extensions.length} total</Badge>
          {criticalCount > 0 ? (
            <Badge tone="info">{criticalCount} critical</Badge>
          ) : null}
        </>
      }
    >
      {certificate.extensions.length === 0 ? (
        <EmptyState>
          This certificate carries no extensions — it is probably an X.509 v1 certificate.
        </EmptyState>
      ) : extensions.length === 0 ? (
        <EmptyState>No extension matches “{query}”.</EmptyState>
      ) : (
        <ul className="divide-y divide-line">
          {extensions.map((extension) => (
            <li key={extension.oid} className="group px-4 py-3">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-[13px] font-medium text-text">
                  {highlight(extension.name, query)}
                </h3>
                {extension.critical ? (
                  <Badge tone="info">critical</Badge>
                ) : (
                  <Badge tone="neutral">non-critical</Badge>
                )}
                {extension.raw ? <Badge tone="neutral">raw</Badge> : null}
                <span className="font-mono text-[11px] text-subtle">
                  {highlight(extension.oid, query)}
                </span>
                <CopyButton
                  value={extension.value}
                  what={`${extension.name} value`}
                  className="ml-auto opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100"
                />
              </div>
              <pre className="mt-1.5 overflow-x-auto rounded-md bg-surface-2 px-3 py-2 font-mono text-[11.5px] leading-relaxed whitespace-pre-wrap text-muted">
                {highlight(extension.value, query)}
              </pre>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
