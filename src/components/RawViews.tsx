'use client';

import { useMemo, useState } from 'react';

import { CopyButton } from '@/components/ui/copy';
import { Badge, Panel } from '@/components/ui/primitives';
import { certificateAsn1Tree } from '@/lib/certificate/asn1-tree';
import { OPENSSL_COMMAND, opensslView } from '@/lib/certificate/openssl-view';
import type { Asn1Node, ParsedCertificate } from '@/lib/certificate/types';
import { cn } from '@/lib/utils';

export function RawCertificate({ certificate }: { certificate: ParsedCertificate }) {
  return (
    <Panel
      title="Raw certificate"
      description="Exactly the PEM this view was built from."
      aside={<CopyButton value={certificate.pem} label="Copy PEM" what="the PEM block" />}
    >
      <pre className="overflow-x-auto px-4 py-3 font-mono text-[11.5px] leading-[1.6] break-all whitespace-pre-wrap text-muted">
        {certificate.pem}
      </pre>
    </Panel>
  );
}

export function OpenSslView({ certificate }: { certificate: ParsedCertificate }) {
  const text = useMemo(() => opensslView(certificate), [certificate]);

  return (
    <div className="space-y-4">
      <Panel
        title="OpenSSL view"
        description="The same data, laid out the way the openssl CLI prints it."
        aside={<CopyButton value={text} label="Copy" what="the openssl output" />}
      >
        <pre className="overflow-x-auto px-4 py-3 font-mono text-[11.5px] leading-[1.6] text-muted">
          {text}
        </pre>
      </Panel>

      <Panel
        title="Equivalent command"
        aside={
          <CopyButton value={OPENSSL_COMMAND} label="Copy" what="the openssl command" />
        }
      >
        <pre className="overflow-x-auto px-4 py-3 font-mono text-[12px] text-text">
          <span className="text-subtle select-none">$ </span>
          {OPENSSL_COMMAND}
        </pre>
      </Panel>
    </div>
  );
}

export function Asn1View({ certificate }: { certificate: ParsedCertificate }) {
  const tree = useMemo(() => certificateAsn1Tree(certificate.der), [certificate]);

  return (
    <Panel
      title="ASN.1 structure"
      description="Offsets and lengths are byte positions in the DER encoding."
    >
      {tree ? (
        <div className="overflow-x-auto px-2 py-2">
          <Asn1Branch node={tree} depth={0} defaultOpen />
        </div>
      ) : (
        <p className="px-4 py-3 text-[13px] text-subtle italic">
          The DER could not be walked.
        </p>
      )}
    </Panel>
  );
}

function Asn1Branch({
  node,
  depth,
  defaultOpen = false,
}: {
  node: Asn1Node;
  depth: number;
  defaultOpen?: boolean;
}) {
  // Deep structures collapse by default so the tree stays scannable.
  const [open, setOpen] = useState(defaultOpen || depth < 2);
  const hasChildren = (node.children?.length ?? 0) > 0;

  return (
    <div style={{ paddingLeft: depth === 0 ? 0 : 14 }}>
      <div
        className={cn(
          'flex items-start gap-1.5 rounded px-1.5 py-[3px] font-mono text-[11.5px] hover:bg-surface-2',
          depth === 0 && 'font-medium',
        )}
      >
        {hasChildren ? (
          <button
            type="button"
            onClick={() => setOpen(!open)}
            aria-expanded={open}
            className="w-3 shrink-0 text-subtle hover:text-text"
          >
            {open ? '▾' : '▸'}
          </button>
        ) : (
          <span className="w-3 shrink-0" aria-hidden />
        )}

        <span className="text-text">{node.name}</span>
        {node.name !== node.type ? (
          <Badge tone="neutral" className="px-1 py-0 text-[9.5px]">
            {node.type}
          </Badge>
        ) : null}
        {node.value !== undefined ? (
          <span className="min-w-0 break-all text-accent">{node.value}</span>
        ) : null}
        <span className="ml-auto shrink-0 pl-3 text-[10px] text-subtle">
          @{node.offset} · {node.length}B
        </span>
      </div>

      {hasChildren && open ? (
        <div className="border-l border-line">
          {node.children!.map((child, index) => (
            <Asn1Branch key={`${child.offset}-${index}`} node={child} depth={depth + 1} />
          ))}
        </div>
      ) : null}
    </div>
  );
}
