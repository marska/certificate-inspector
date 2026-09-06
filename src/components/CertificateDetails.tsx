'use client';

import type { ReactNode } from 'react';

import { CopyButton } from '@/components/ui/copy';
import { FieldList, filterFields, type FieldSpec } from '@/components/ui/field';
import { Badge, EmptyState, Panel, Segmented, Tick } from '@/components/ui/primitives';
import { ValidityBar } from '@/components/CertificateStatus';
import type { ParsedCertificate } from '@/lib/certificate/types';
import { cn, matchesQuery } from '@/lib/utils';
import {
  accessFields,
  basicConstraintsFields,
  fingerprintFields,
  publicKeyFields,
  signatureFields,
  summaryFields,
  validityFields,
  type TimeZoneMode,
} from '@/lib/view-model';

export interface DetailsProps {
  certificate: ParsedCertificate;
  query: string;
  timeZone: TimeZoneMode;
  onTimeZoneChange: (mode: TimeZoneMode) => void;
  fingerprintColons: boolean;
  onFingerprintColonsChange: (value: boolean) => void;
}

/**
 * A panel that hides itself when the search box excludes all of its content,
 * so searching narrows the page instead of just dimming it.
 */
function SearchPanel({
  title,
  query,
  fields,
  aside,
  description,
  children,
  alwaysShowChildren = false,
}: {
  title: string;
  query: string;
  fields?: FieldSpec[];
  aside?: ReactNode;
  description?: string;
  children?: ReactNode;
  /** Keep children visible even when only the title matched. */
  alwaysShowChildren?: boolean;
}) {
  const titleMatches = matchesQuery(query, title, description);
  const visibleFields = fields ? filterFields(fields, query) : [];
  const hasFieldMatches = visibleFields.length > 0;

  if (query.trim() && !titleMatches && !hasFieldMatches && !alwaysShowChildren) {
    return null;
  }

  return (
    <Panel title={title} aside={aside} description={description}>
      {fields ? (
        <FieldList fields={titleMatches ? fields : visibleFields} query={query} />
      ) : null}
      {children}
    </Panel>
  );
}

export function CertificateDetails({
  certificate,
  query,
  timeZone,
  onTimeZoneChange,
  fingerprintColons,
  onFingerprintColonsChange,
}: DetailsProps) {
  const sections: ReactNode[] = [
    <SearchPanel
      key="summary"
      title="Summary"
      query={query}
      fields={summaryFields(certificate, timeZone)}
      aside={
        <Segmented
          aria-label="Time zone"
          options={[
            { value: 'utc', label: 'UTC' },
            { value: 'local', label: 'Local time' },
          ]}
          value={timeZone}
          onChange={onTimeZoneChange}
        />
      }
    />,

    <SearchPanel
      key="validity"
      title="Validity"
      query={query}
      fields={validityFields(certificate, timeZone)}
      description="Dates as recorded in the certificate."
    >
      <div className="border-t border-line">
        <ValidityBar certificate={certificate} />
      </div>
    </SearchPanel>,

    <SanSection key="san" certificate={certificate} query={query} />,

    <SearchPanel
      key="publicKey"
      title="Public Key"
      query={query}
      fields={publicKeyFields(certificate)}
    />,

    <SignatureSection key="signature" certificate={certificate} query={query} />,

    <KeyUsageSection key="keyUsage" certificate={certificate} query={query} />,

    <ExtendedKeyUsageSection key="eku" certificate={certificate} query={query} />,

    <SearchPanel
      key="basicConstraints"
      title="Basic Constraints"
      query={query}
      fields={basicConstraintsFields(certificate)}
      aside={
        <Badge tone={certificate.isCA ? 'info' : 'neutral'}>
          {certificate.isCA
            ? certificate.isSelfSigned
              ? 'Root CA'
              : 'Intermediate CA'
            : 'Leaf certificate'}
        </Badge>
      }
    />,

    <SearchPanel
      key="fingerprints"
      title="Fingerprints"
      query={query}
      fields={fingerprintFields(certificate, fingerprintColons)}
      aside={
        <Segmented
          aria-label="Fingerprint format"
          options={[
            { value: 'colons', label: 'With colons' },
            { value: 'plain', label: 'Without' },
          ]}
          value={fingerprintColons ? 'colons' : 'plain'}
          onChange={(value) => onFingerprintColonsChange(value === 'colons')}
        />
      }
    />,
  ];

  const access = accessFields(certificate);
  if (access.length > 0) {
    sections.push(
      <SearchPanel
        key="access"
        title="URLs & Key Identifiers"
        query={query}
        fields={access}
        description="OCSP, CA Issuers, CRL distribution points and key identifiers."
      />,
    );
  }

  const rendered = sections.filter(Boolean);

  return (
    <div className="space-y-4">
      {rendered.length === 0 ? (
        <Panel title="Search">
          <EmptyState>
            Nothing matches “{query}”. Try <code className="font-mono">issuer</code>,{' '}
            <code className="font-mono">SAN</code>, <code className="font-mono">OCSP</code>,{' '}
            <code className="font-mono">key usage</code> or{' '}
            <code className="font-mono">serial</code>.
          </EmptyState>
        </Panel>
      ) : (
        rendered
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Sections with custom rendering                                      */
/* ------------------------------------------------------------------ */

function SanSection({
  certificate,
  query,
}: {
  certificate: ParsedCertificate;
  query: string;
}) {
  const sans = certificate.subjectAlternativeNames;
  const titleMatches = matchesQuery(
    query,
    'Subject Alternative Names',
    'san',
    'dns',
    'alt name',
  );
  const visible = titleMatches
    ? sans
    : sans.filter((san) => matchesQuery(query, san.value, san.label, san.type));

  if (query.trim() && !titleMatches && visible.length === 0) return null;

  return (
    <Panel
      title="Subject Alternative Names"
      aside={
        <>
          <Badge tone="neutral">Total SANs: {sans.length}</Badge>
          {sans.length > 0 ? (
            <CopyButton
              value={sans.map((san) => san.value).join('\n')}
              label="Copy all"
              what="all subject alternative names"
            />
          ) : null}
        </>
      }
    >
      {sans.length === 0 ? (
        <EmptyState>
          This certificate has no SAN extension. Browsers ignore the Common Name, so a
          certificate without SANs will not validate for any hostname.
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line">
          {visible.map((san, index) => (
            <li
              key={`${san.type}-${san.value}-${index}`}
              className="group grid grid-cols-[4.5rem_1fr_auto] items-center gap-3 px-4 py-2"
            >
              <Badge tone={san.type === 'dns' ? 'accent' : 'neutral'} className="justify-center">
                {san.label}
              </Badge>
              <span className="min-w-0 font-mono text-[12.5px] break-all text-text">
                {san.value}
              </span>
              <CopyButton
                value={san.value}
                what={`${san.label} ${san.value}`}
                className="opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100"
              />
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function SignatureSection({
  certificate,
  query,
}: {
  certificate: ParsedCertificate;
  query: string;
}) {
  const fields = signatureFields(certificate);
  const titleMatches = matchesQuery(query, 'Signature', 'hash', 'algorithm');
  const visible = filterFields(fields, query);
  if (query.trim() && !titleMatches && visible.length === 0) return null;

  return (
    <Panel
      title="Signature"
      aside={
        certificate.signature.weak ? <Badge tone="warning">Weak algorithm</Badge> : null
      }
    >
      {certificate.signature.weak ? (
        <div className="border-b border-warning-border bg-warning-soft px-4 py-2.5">
          <p className="text-[13px] font-medium text-warning">
            <span aria-hidden className="mr-1">
              ⚠
            </span>
            Weak signature algorithm
          </p>
          <p className="mt-0.5 text-[12px] leading-relaxed text-muted">
            {certificate.signature.weakReason}
          </p>
        </div>
      ) : null}
      <FieldList fields={titleMatches ? fields : visible} query={query} />
    </Panel>
  );
}

function KeyUsageSection({
  certificate,
  query,
}: {
  certificate: ParsedCertificate;
  query: string;
}) {
  const usages = certificate.keyUsage;
  const titleMatches = matchesQuery(query, 'Key Usage', 'keyusage');
  const visible = titleMatches
    ? usages
    : usages.filter((usage) => matchesQuery(query, usage.name));

  if (query.trim() && !titleMatches && visible.length === 0) return null;

  return (
    <Panel
      title="Key Usage"
      aside={
        usages.length > 0 ? (
          <Badge tone="neutral">
            {usages.filter((usage) => usage.enabled).length} of {usages.length}
          </Badge>
        ) : null
      }
    >
      {usages.length === 0 ? (
        <EmptyState>
          No Key Usage extension — the key is not restricted to particular operations.
        </EmptyState>
      ) : (
        <ul className="grid grid-cols-1 gap-x-6 gap-y-1 px-4 py-3 sm:grid-cols-2">
          {visible.map((usage) => (
            <li key={usage.name} className="flex items-center gap-2">
              <Tick ok={usage.enabled} />
              <span
                className={cn(
                  'text-[13px]',
                  usage.enabled ? 'text-text' : 'text-subtle line-through decoration-1',
                )}
              >
                {usage.name}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function ExtendedKeyUsageSection({
  certificate,
  query,
}: {
  certificate: ParsedCertificate;
  query: string;
}) {
  const purposes = certificate.extendedKeyUsage;
  const titleMatches = matchesQuery(query, 'Extended Key Usage', 'eku');
  const visible = titleMatches
    ? purposes
    : purposes.filter((purpose) => matchesQuery(query, purpose.name, purpose.oid));

  if (query.trim() && !titleMatches && visible.length === 0) return null;

  return (
    <Panel title="Extended Key Usage">
      {purposes.length === 0 ? (
        <EmptyState>
          No Extended Key Usage extension — the certificate is not limited to a specific
          purpose.
        </EmptyState>
      ) : (
        <ul className="divide-y divide-line">
          {visible.map((purpose) => (
            <li
              key={purpose.oid}
              className="group flex items-center gap-2.5 px-4 py-2"
            >
              <Tick ok />
              <div className="min-w-0 flex-1">
                <p className="text-[13px] text-text">{purpose.name}</p>
                <p className="font-mono text-[11px] text-subtle">{purpose.oid}</p>
              </div>
              <CopyButton
                value={purpose.oid}
                what={`OID ${purpose.oid}`}
                className="opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100"
              />
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
