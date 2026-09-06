'use client';

import { Badge, Panel } from '@/components/ui/primitives';
import type {
  CertificateChain as Chain,
  CertificateRole,
  ParsedCertificate,
} from '@/lib/certificate/types';
import { cn } from '@/lib/utils';
import { STATUS_LABEL, STATUS_TONE } from '@/lib/view-model';

const ROLE_LABEL: Record<CertificateRole, string> = {
  leaf: 'Leaf certificate',
  intermediate: 'Intermediate CA',
  root: 'Root CA',
  unknown: 'Certificate',
};

const CHAIN_STATUS: Record<
  Chain['status'],
  { label: string; tone: 'success' | 'warning' | 'danger' | 'neutral'; glyph: string }
> = {
  valid: { label: 'Chain appears valid', tone: 'success', glyph: '✓' },
  incomplete: { label: 'Chain incomplete', tone: 'warning', glyph: '!' },
  invalid: { label: 'Chain has errors', tone: 'danger', glyph: '✕' },
  unknown: { label: 'Chain unknown', tone: 'neutral', glyph: '?' },
};

export function CertificateChainPanel({
  chain,
  selectedId,
  onSelect,
}: {
  chain: Chain;
  selectedId?: string;
  onSelect: (id: string) => void;
}) {
  const status = CHAIN_STATUS[chain.status];
  const ordered = chain.certificates.filter(
    (certificate) => !chain.unrelated.includes(certificate),
  );

  return (
    <Panel
      title="Certificate Chain"
      aside={
        <Badge tone={status.tone}>
          <span aria-hidden>{status.glyph}</span>
          {status.label}
        </Badge>
      }
    >
      <div className="px-3 py-3">
        <ol className="space-y-0">
          {ordered.map((certificate, index) => (
            <li key={certificate.id}>
              <ChainNode
                certificate={certificate}
                selected={certificate.id === selectedId}
                onSelect={onSelect}
              />
              {index < ordered.length - 1 ? <Connector /> : null}
            </li>
          ))}
        </ol>

        {chain.missingIssuer ? (
          <>
            <Connector dashed />
            <div className="rounded-md border border-dashed border-line-strong px-3 py-2.5">
              <p className="text-[11px] tracking-wide text-subtle uppercase">
                Missing issuer
              </p>
              <p className="mt-0.5 font-mono text-[11.5px] break-words text-muted">
                {chain.missingIssuer}
              </p>
            </div>
          </>
        ) : null}

        {chain.unrelated.length > 0 ? (
          <div className="mt-4 space-y-2 border-t border-line pt-3">
            <p className="text-[11px] tracking-wide text-subtle uppercase">
              Not part of this chain
            </p>
            {chain.unrelated.map((certificate) => (
              <ChainNode
                key={certificate.id}
                certificate={certificate}
                selected={certificate.id === selectedId}
                onSelect={onSelect}
                muted
              />
            ))}
          </div>
        ) : null}
      </div>

      <TrustSummary chain={chain} />
    </Panel>
  );
}

function ChainNode({
  certificate,
  selected,
  onSelect,
  muted = false,
}: {
  certificate: ParsedCertificate;
  selected: boolean;
  onSelect: (id: string) => void;
  muted?: boolean;
}) {
  const validityTone = STATUS_TONE[certificate.validity.status];
  const dot =
    validityTone === 'success'
      ? 'bg-success'
      : validityTone === 'danger'
        ? 'bg-danger'
        : 'bg-warning';

  return (
    <button
      type="button"
      onClick={() => onSelect(certificate.id)}
      aria-current={selected ? 'true' : undefined}
      className={cn(
        'w-full rounded-md border px-3 py-2.5 text-left transition-colors',
        'focus-visible:ring-2 focus-visible:ring-accent/60 focus-visible:outline-none',
        selected
          ? 'border-accent-border bg-accent-soft'
          : 'border-line bg-surface hover:border-line-strong hover:bg-surface-2',
        muted && !selected && 'opacity-80',
      )}
    >
      <div className="flex items-start gap-2">
        <span className={cn('mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full', dot)} aria-hidden />
        <div className="min-w-0 flex-1">
          <p
            className="truncate font-mono text-[12.5px] font-medium text-text"
            title={certificate.label}
          >
            {certificate.label}
          </p>
          <p className="mt-0.5 flex items-center gap-1.5 text-[11px] text-subtle">
            <span>{ROLE_LABEL[certificate.role ?? 'unknown']}</span>
            <span aria-hidden>·</span>
            <span
              className={cn(
                certificate.validity.status === 'valid' ? 'text-subtle' : 'text-warning',
              )}
            >
              {STATUS_LABEL[certificate.validity.status]}
            </span>
          </p>
        </div>
      </div>
    </button>
  );
}

function Connector({ dashed = false }: { dashed?: boolean }) {
  return (
    <div className="flex h-6 items-center justify-center" aria-hidden>
      <div className="relative flex h-full flex-col items-center">
        <span
          className={cn(
            'w-px flex-1',
            dashed
              ? 'border-l border-dashed border-line-strong'
              : 'bg-line-strong',
          )}
        />
        <span className="-mt-1 text-[10px] leading-none text-line-strong">▼</span>
      </div>
    </div>
  );
}

/**
 * Spec §31: cryptographic verification and system trust are different claims,
 * and this tool can only speak to the first one.
 */
function TrustSummary({ chain }: { chain: Chain }) {
  const crypto = chain.cryptographicStatus;
  const cryptoTone =
    crypto === 'valid' ? 'success' : crypto === 'invalid' ? 'danger' : 'neutral';
  const cryptoLabel =
    crypto === 'valid' ? 'Valid' : crypto === 'invalid' ? 'Invalid' : 'Not verified';

  return (
    <div className="grid grid-cols-2 gap-px border-t border-line bg-line">
      <div className="bg-surface px-3.5 py-2.5">
        <p className="text-[10.5px] tracking-wide text-subtle uppercase">
          Cryptographic chain
        </p>
        <p className="mt-1">
          <Badge tone={cryptoTone}>{cryptoLabel}</Badge>
        </p>
      </div>
      <div className="bg-surface px-3.5 py-2.5">
        <p className="text-[10.5px] tracking-wide text-subtle uppercase">System trust</p>
        <p className="mt-1">
          <Badge tone="neutral" title="This tool does not use a trust store.">
            Unknown
          </Badge>
        </p>
      </div>
      <div className="col-span-2 bg-surface px-3.5 pb-3 text-[11px] leading-relaxed text-subtle">
        Signature and structure checks run locally. Whether a root is trusted by your OS or
        browser is not something this tool can tell you — it ships no trust store.
      </div>
    </div>
  );
}
