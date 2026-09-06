'use client';

import { Badge } from '@/components/ui/primitives';
import type { ParsedCertificate } from '@/lib/certificate/types';
import { cn } from '@/lib/utils';
import {
  STATUS_LABEL,
  STATUS_TONE,
  certificateKind,
  expiryPhrase,
  formatDate,
  type TimeZoneMode,
} from '@/lib/view-model';

/** The headline card described in spec §3. */
export function CertificateStatus({
  certificate,
  timeZone,
}: {
  certificate: ParsedCertificate;
  timeZone: TimeZoneMode;
}) {
  const { validity } = certificate;
  const tone = STATUS_TONE[validity.status];

  const accent =
    tone === 'success'
      ? 'before:bg-success'
      : tone === 'danger'
        ? 'before:bg-danger'
        : 'before:bg-warning';

  return (
    <section
      className={cn(
        'relative overflow-hidden rounded-lg border border-line bg-surface pl-1',
        'before:absolute before:inset-y-0 before:left-0 before:w-1 before:content-[""]',
        accent,
      )}
      style={{ boxShadow: 'var(--shadow)' }}
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line px-4 py-3">
        <Badge tone={tone} className="px-2.5 py-1 text-xs">
          <span aria-hidden>
            {validity.status === 'valid' ? '✓' : validity.status === 'expired' ? '✕' : '!'}
          </span>
          {STATUS_LABEL[validity.status]}
        </Badge>
        <span className="text-[13px] font-medium text-text">
          {expiryPhrase(certificate)}
        </span>
        <Badge tone="neutral">{certificateKind(certificate)}</Badge>
        {certificate.signature.weak ? (
          <Badge tone="warning">Weak signature</Badge>
        ) : null}
      </div>

      <dl className="grid grid-cols-1 divide-y divide-line sm:grid-cols-2 sm:divide-y-0 lg:grid-cols-4 lg:divide-x">
        <Cell label="Common Name" value={certificate.commonName ?? '—'} mono />
        <Cell
          label="Issued by"
          value={certificate.issuer.attributes.find((a) => a.shortName === 'CN')?.value ??
            certificate.issuer.oneLine ??
            '—'}
        />
        <Cell label="Valid from" value={formatDate(validity.notBefore, timeZone)} mono />
        <Cell label="Valid until" value={formatDate(validity.notAfter, timeZone)} mono />
      </dl>

      <ValidityBar certificate={certificate} />
    </section>
  );
}

function Cell({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0 px-4 py-3">
      <dt className="text-[11px] tracking-wide text-subtle uppercase">{label}</dt>
      <dd
        className={cn(
          'mt-1 truncate text-[13px] text-text',
          mono && 'font-mono text-[12.5px]',
        )}
        title={value}
      >
        {value}
      </dd>
    </div>
  );
}

/** Visual share of the validity window that has already elapsed (spec §6). */
export function ValidityBar({ certificate }: { certificate: ParsedCertificate }) {
  const { validity } = certificate;
  const percent = Math.round(validity.elapsedFraction * 100);
  const fill =
    validity.status === 'expired'
      ? 'bg-danger'
      : validity.status === 'expiring-soon'
        ? 'bg-warning'
        : 'bg-success';

  return (
    <div className="px-4 pt-1 pb-3.5">
      <div
        role="progressbar"
        aria-label="Share of the validity period already elapsed"
        aria-valuenow={percent}
        aria-valuemin={0}
        aria-valuemax={100}
        className="h-1.5 w-full overflow-hidden rounded-full bg-surface-3"
      >
        <div
          className={cn('h-full rounded-full transition-[width]', fill)}
          style={{ width: `${Math.max(percent, 1)}%` }}
        />
      </div>
      <div className="mt-1.5 flex justify-between font-mono text-[10.5px] text-subtle">
        <span>{validity.notBefore.toISOString().slice(0, 10)}</span>
        <span>{percent}% elapsed</span>
        <span>{validity.notAfter.toISOString().slice(0, 10)}</span>
      </div>
    </div>
  );
}
