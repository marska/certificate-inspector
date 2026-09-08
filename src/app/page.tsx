'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { CertificateChainPanel } from '@/components/CertificateChain';
import { CertificateDetails } from '@/components/CertificateDetails';
import { CertificateExtensions } from '@/components/CertificateExtensions';
import { CertificateInput } from '@/components/CertificateInput';
import { CertificateStatus } from '@/components/CertificateStatus';
import { ChainReport } from '@/components/ChainReport';
import { Asn1View, OpenSslView, RawCertificate } from '@/components/RawViews';
import {
  IssueList,
  PrivacyNote,
  PrivateKeyAlert,
} from '@/components/SecurityWarnings';
import { ThemeToggle } from '@/components/ThemeToggle';
import { Badge, Button, Panel } from '@/components/ui/primitives';
import { analyzeInput } from '@/lib/certificate';
import { decodeInput } from '@/lib/certificate/decode-input';
import type { AnalysisResult } from '@/lib/certificate/types';
import { cn } from '@/lib/utils';
import { APP_VERSION } from '@/lib/version';
import type { TimeZoneMode } from '@/lib/view-model';

const TABS = [
  { id: 'details', label: 'Details' },
  { id: 'extensions', label: 'Extensions' },
  { id: 'chain', label: 'Chain' },
  { id: 'raw', label: 'Raw' },
  { id: 'openssl', label: 'OpenSSL' },
  { id: 'asn1', label: 'ASN.1' },
] as const;

type TabId = (typeof TABS)[number]['id'];

export default function Home() {
  const [text, setText] = useState('');
  const [binary, setBinary] = useState<Uint8Array | undefined>();
  const [fileInfo, setFileInfo] = useState<
    { name: string; formatLabel: string } | undefined
  >();

  const [result, setAnalysis] = useState<AnalysisResult | undefined>();
  const [busy, setBusy] = useState(false);
  const [lastError, setCrash] = useState<string | undefined>();

  const [selectedId, setSelectedId] = useState<string | undefined>();
  const [query, setQuery] = useState('');
  const [tab, setTab] = useState<TabId>('details');
  const [timeZone, setTimeZone] = useState<TimeZoneMode>('utc');
  const [fingerprintColons, setFingerprintColons] = useState(true);
  const [samplePending, setSamplePending] = useState(false);

  const searchRef = useRef<HTMLInputElement>(null);

  /* ---------------- analysis, debounced ---------------- */

  useEffect(() => {
    const source: string | Uint8Array = binary ?? text;
    const empty = binary ? binary.length === 0 : !text.trim();
    // Nothing to do for empty input: what is rendered is derived from
    // `hasInput` below, so no state needs clearing here.
    if (empty) return;

    let cancelled = false;
    const timer = setTimeout(() => {
      setBusy(true);
      analyzeInput(source)
        .then((result) => {
          if (cancelled) return;
          setAnalysis(result);
          setCrash(undefined);
        })
        .catch((error: unknown) => {
          if (cancelled) return;
          setAnalysis(undefined);
          setCrash(error instanceof Error ? error.message : String(error));
        })
        .finally(() => {
          if (!cancelled) setBusy(false);
        });
    }, 140);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [text, binary]);

  /* ---------------- keyboard: "/" focuses search ---------------- */

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const typing =
        target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.isContentEditable);
      if (event.key === '/' && !typing) {
        event.preventDefault();
        searchRef.current?.focus();
      }
      if (event.key === 'Escape' && document.activeElement === searchRef.current) {
        setQuery('');
        searchRef.current?.blur();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  /* ---------------- derived ---------------- */

  // Everything below renders from `hasInput`, so clearing the box hides the
  // previous result without an extra state update.
  const hasInput = Boolean(binary?.length || text.trim());
  const analysis = hasInput ? result : undefined;
  const crash = hasInput ? lastError : undefined;

  const certificates = useMemo(
    () => analysis?.chain.certificates ?? [],
    [analysis],
  );
  const selected =
    certificates.find((certificate) => certificate.id === selectedId) ??
    analysis?.chain.leaf ??
    certificates[0];

  const onTextChange = useCallback((value: string) => {
    setText(value);
    setBinary(undefined);
    setFileInfo(undefined);
  }, []);

  const onBinary = useCallback((bytes: Uint8Array, name: string) => {
    // Decoding is synchronous, so a binary file can be shown as PEM straight
    // away and behave exactly like pasted text from then on.
    const decoded = decodeInput(bytes);
    setFileInfo({ name, formatLabel: decoded.detectedFormatLabel });
    setSelectedId(undefined);
    if (decoded.blocks.length > 0) {
      setBinary(undefined);
      setText(decoded.blocks.map((block) => block.pem).join('\n\n'));
    } else {
      setText('');
      setBinary(bytes);
    }
  }, []);

  const onClear = useCallback(() => {
    setText('');
    setBinary(undefined);
    setFileInfo(undefined);
    setAnalysis(undefined);
    setSelectedId(undefined);
    setQuery('');
    setCrash(undefined);
  }, []);

  const onLoadSample = useCallback(async () => {
    setSamplePending(true);
    try {
      const { buildSampleChain } = await import('@/lib/sample-chain');
      onTextChange(await buildSampleChain());
      setSelectedId(undefined);
    } catch (error) {
      setCrash(
        `Could not generate the sample chain: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    } finally {
      setSamplePending(false);
    }
  }, [onTextChange]);

  const issues = analysis?.issues ?? [];

  return (
    <div className="mx-auto flex w-full max-w-[1400px] flex-1 flex-col gap-5 px-4 py-5 sm:px-6 lg:px-8">
      <SiteHeader />

      <CertificateInput
        value={text}
        onChange={onTextChange}
        onBinary={onBinary}
        formatLabel={
          hasInput && analysis ? analysis.decode.detectedFormatLabel : undefined
        }
        certificateCount={certificates.length}
        fileName={fileInfo?.name}
        onClear={onClear}
        onLoadSample={() => void onLoadSample()}
      />

      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
        <PrivacyNote />
        {samplePending ? (
          <span className="text-[11.5px] text-subtle">Generating a demo chain…</span>
        ) : null}
        {fileInfo && !binary ? (
          <span className="text-[11.5px] text-subtle">
            Loaded <span className="font-mono">{fileInfo.name}</span> (
            {fileInfo.formatLabel}) — shown above as PEM.
          </span>
        ) : null}
      </div>

      {analysis?.decode.containsPrivateKey ? <PrivateKeyAlert /> : null}

      {crash ? (
        <IssueList
          issues={[
            {
              severity: 'error',
              code: 'PARSE_FAILED',
              message: 'Something went wrong while reading this input.',
              detail: crash,
            },
          ]}
        />
      ) : null}

      <IssueList issues={issues} />

      {!hasInput ? (
        <EmptyIntro onLoadSample={() => void onLoadSample()} />
      ) : !selected ? (
        busy ? (
          <p className="py-8 text-center text-[13px] text-subtle">Decoding…</p>
        ) : null
      ) : (
        <>
          <CertificateStatus certificate={selected} timeZone={timeZone} />

          <div className="grid grid-cols-1 items-start gap-5 lg:grid-cols-[19rem_minmax(0,1fr)]">
            <div className="lg:sticky lg:top-5">
              {analysis ? (
                <CertificateChainPanel
                  chain={analysis.chain}
                  selectedId={selected.id}
                  onSelect={setSelectedId}
                />
              ) : null}
            </div>

            <div className="min-w-0 space-y-4">
              <div className="flex flex-wrap items-center gap-2">
                <nav
                  aria-label="Certificate views"
                  className="flex flex-1 flex-wrap items-center gap-0.5 rounded-lg border border-line bg-surface p-1"
                  style={{ boxShadow: 'var(--shadow)' }}
                >
                  {TABS.map((entry) => (
                    <button
                      key={entry.id}
                      type="button"
                      onClick={() => setTab(entry.id)}
                      aria-current={tab === entry.id ? 'page' : undefined}
                      className={cn(
                        'rounded-md px-3 py-1.5 text-[12.5px] font-medium transition-colors',
                        'focus-visible:ring-2 focus-visible:ring-accent/60 focus-visible:outline-none',
                        tab === entry.id
                          ? 'bg-accent-soft text-accent'
                          : 'text-muted hover:bg-surface-2 hover:text-text',
                      )}
                    >
                      {entry.label}
                      {entry.id === 'chain' && analysis?.chain.issues.length ? (
                        <span className="ml-1.5 text-[10px] text-subtle">
                          {analysis.chain.issues.length}
                        </span>
                      ) : null}
                    </button>
                  ))}
                </nav>

                <SearchBox ref={searchRef} value={query} onChange={setQuery} />
              </div>

              {tab === 'details' ? (
                <CertificateDetails
                  certificate={selected}
                  query={query}
                  timeZone={timeZone}
                  onTimeZoneChange={setTimeZone}
                  fingerprintColons={fingerprintColons}
                  onFingerprintColonsChange={setFingerprintColons}
                />
              ) : null}

              {tab === 'extensions' ? (
                <CertificateExtensions certificate={selected} query={query} />
              ) : null}

              {tab === 'chain' && analysis ? (
                <ChainReport
                  chain={analysis.chain}
                  query={query}
                  onSelect={setSelectedId}
                />
              ) : null}

              {tab === 'raw' ? <RawCertificate certificate={selected} /> : null}
              {tab === 'openssl' ? <OpenSslView certificate={selected} /> : null}
              {tab === 'asn1' ? <Asn1View certificate={selected} /> : null}
            </div>
          </div>
        </>
      )}

      <SiteFooter />
    </div>
  );
}

/* ------------------------------------------------------------------ */

function SiteHeader() {
  return (
    <header className="flex flex-wrap items-center justify-between gap-3">
      <div className="flex items-center gap-2.5">
        <span
          aria-hidden
          className="flex h-8 w-8 items-center justify-center rounded-md border border-line bg-surface text-accent"
          style={{ boxShadow: 'var(--shadow)' }}
        >
          <svg viewBox="0 0 20 20" className="h-4 w-4" fill="none">
            <path
              d="M10 2.5 16 5v4.6c0 3.5-2.4 6.6-6 7.9-3.6-1.3-6-4.4-6-7.9V5l6-2.5Z"
              stroke="currentColor"
              strokeWidth="1.4"
              strokeLinejoin="round"
            />
            <path
              d="m7.3 9.9 1.9 1.9 3.5-3.6"
              stroke="currentColor"
              strokeWidth="1.4"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </span>
        <div>
          <h1 className="text-[15px] leading-5 font-semibold tracking-tight text-text">
            Certificate Inspector
          </h1>
          <p className="text-[11.5px] text-subtle">
            X.509 decoder and chain validator that runs in your browser
          </p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <Badge tone="success" className="hidden sm:inline-flex">
          <span aria-hidden>🔒</span> Local only
        </Badge>
        <ThemeToggle />
      </div>
    </header>
  );
}

function SearchBox({
  ref,
  value,
  onChange,
}: {
  ref: React.Ref<HTMLInputElement>;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="relative min-w-[13rem] flex-1 sm:max-w-xs">
      <svg
        viewBox="0 0 16 16"
        aria-hidden
        className="pointer-events-none absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-subtle"
        fill="none"
      >
        <circle cx="7" cy="7" r="4.25" stroke="currentColor" strokeWidth="1.3" />
        <path d="m10.5 10.5 3 3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
      </svg>
      <input
        ref={ref}
        type="search"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder="Search certificate properties…"
        aria-label="Search certificate properties"
        className={cn(
          'h-9 w-full rounded-lg border border-line bg-surface pr-10 pl-8',
          'text-[12.5px] text-text placeholder:text-subtle',
          'outline-none focus:border-accent-border focus:ring-2 focus:ring-accent/25',
        )}
        style={{ boxShadow: 'var(--shadow)' }}
      />
      {!value ? (
        <kbd className="pointer-events-none absolute top-1/2 right-2.5 -translate-y-1/2 rounded border border-line bg-surface-2 px-1 font-mono text-[10px] text-subtle">
          /
        </kbd>
      ) : null}
    </div>
  );
}

function EmptyIntro({ onLoadSample }: { onLoadSample: () => void }) {
  return (
    <Panel title="What this does">
      <div className="grid grid-cols-1 gap-px bg-line sm:grid-cols-3">
        <Item title="Paste anything">
          PEM, raw Base64, Base64 that wraps a PEM file, hex, DER, a PKCS#7 bundle or a
          whole chain. The format is detected for you.
        </Item>
        <Item title="See everything">
          Subject, issuer, validity, SANs, key, signature, key usage, basic constraints,
          fingerprints, every extension, the ASN.1 tree and an openssl-style view.
        </Item>
        <Item title="Check the chain">
          Certificates are ordered into a chain and each hop is verified: issuer names,
          AKI/SKI, and the actual signatures.
        </Item>
      </div>
      <div className="flex flex-wrap items-center gap-3 border-t border-line px-4 py-3">
        <Button variant="primary" size="md" onClick={onLoadSample}>
          Load a sample chain
        </Button>
        <p className="text-[12px] text-subtle">
          Generated locally in your browser — no real certificate is involved.
        </p>
      </div>
    </Panel>
  );
}

function Item({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-surface px-4 py-3.5">
      <h3 className="text-[13px] font-medium text-text">{title}</h3>
      <p className="mt-1 text-[12px] leading-relaxed text-muted">{children}</p>
    </div>
  );
}

function SiteFooter() {
  return (
    <footer className="mt-auto border-t border-line pt-4 text-[11.5px] leading-relaxed text-subtle">
      <p>
        Certificate Inspector parses X.509 certificates entirely in the browser using
        WebCrypto. Nothing you paste is uploaded, logged, stored or sent to analytics.
      </p>
      <p className="mt-1">
        Signature verification proves the cryptographic relations between the certificates
        you supplied. It says nothing about whether your operating system or browser trusts
        the root — this tool carries no trust store.
      </p>
      <p className="mt-3">
        Certificate Inspector <span className="font-mono">v{APP_VERSION}</span>
      </p>
    </footer>
  );
}
