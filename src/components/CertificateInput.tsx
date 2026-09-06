'use client';

import { useCallback, useId, useRef, useState } from 'react';

import { Badge, Button } from '@/components/ui/primitives';
import { cn } from '@/lib/utils';

const ACCEPTED = '.crt,.cer,.pem,.der,.cert,.p7b,.p7c,.txt,application/x-x509-ca-cert';

export interface CertificateInputProps {
  value: string;
  onChange: (value: string) => void;
  /** Called when a binary file is dropped, so DER survives untouched. */
  onBinary: (bytes: Uint8Array, fileName: string) => void;
  formatLabel?: string;
  certificateCount: number;
  fileName?: string;
  onClear: () => void;
  onLoadSample: () => void;
}

export function CertificateInput({
  value,
  onChange,
  onBinary,
  formatLabel,
  certificateCount,
  fileName,
  onClear,
  onLoadSample,
}: CertificateInputProps) {
  const [dragging, setDragging] = useState(false);
  const [fileError, setFileError] = useState<string | undefined>();
  const inputRef = useRef<HTMLInputElement>(null);
  const textareaId = useId();

  const readFile = useCallback(
    async (file: File) => {
      setFileError(undefined);
      if (file.size > 4 * 1024 * 1024) {
        setFileError(`${file.name} is larger than 4 MB — that is not a certificate.`);
        return;
      }
      const bytes = new Uint8Array(await file.arrayBuffer());
      onBinary(bytes, file.name);
    },
    [onBinary],
  );

  const onDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault();
      setDragging(false);
      const file = event.dataTransfer.files?.[0];
      if (file) void readFile(file);
    },
    [readFile],
  );

  return (
    <div
      onDragOver={(event) => {
        event.preventDefault();
        setDragging(true);
      }}
      onDragLeave={(event) => {
        // Ignore drags moving between children of the drop zone.
        if (!event.currentTarget.contains(event.relatedTarget as Node)) {
          setDragging(false);
        }
      }}
      onDrop={onDrop}
      className={cn(
        'relative rounded-lg border bg-surface transition-colors',
        dragging ? 'border-accent ring-2 ring-accent/25' : 'border-line',
      )}
      style={{ boxShadow: 'var(--shadow)' }}
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-3 py-2">
        <div className="flex items-center gap-2">
          <label
            htmlFor={textareaId}
            className="text-[13px] font-semibold tracking-tight text-text"
          >
            Paste certificate
          </label>
          {formatLabel ? (
            <Badge tone="accent" title="Detected input format">
              {formatLabel}
            </Badge>
          ) : null}
          {certificateCount > 1 ? (
            <Badge tone="neutral">{certificateCount} certificates</Badge>
          ) : null}
          {fileName ? <Badge tone="neutral">{fileName}</Badge> : null}
        </div>

        <div className="flex items-center gap-1.5">
          <Button variant="ghost" onClick={onLoadSample}>
            Load sample
          </Button>
          <Button variant="ghost" onClick={() => inputRef.current?.click()}>
            Choose file
          </Button>
          <Button variant="ghost" onClick={onClear} disabled={!value && !fileName}>
            Clear
          </Button>
        </div>
      </div>

      <textarea
        id={textareaId}
        value={value}
        spellCheck={false}
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="off"
        data-1p-ignore
        onChange={(event) => onChange(event.target.value)}
        placeholder={
          '-----BEGIN CERTIFICATE-----\nMIIEFTCCAv2gAwIBAgIU...\n-----END CERTIFICATE-----\n\n' +
          'Base64, DER, a whole chain or a bundle also work. Or drop a .crt / .cer / .pem / .der file here.'
        }
        rows={value ? 8 : 6}
        className={cn(
          'block max-h-[45vh] min-h-[8.5rem] w-full resize-y bg-transparent px-3.5 py-3',
          'font-mono text-[12.5px] leading-[1.55] text-text placeholder:text-subtle/70',
          'outline-none',
        )}
      />

      <input
        ref={inputRef}
        type="file"
        accept={ACCEPTED}
        className="sr-only"
        onChange={(event) => {
          const file = event.target.files?.[0];
          if (file) void readFile(file);
          event.target.value = '';
        }}
      />

      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line px-3.5 py-2 text-[11px] text-subtle">
        <span>
          Drop a file anywhere on this box, or paste — decoding starts as you type.
        </span>
        {fileError ? <span className="text-danger">{fileError}</span> : null}
      </div>

      {dragging ? (
        <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center rounded-lg bg-accent-soft/85">
          <p className="text-sm font-medium text-accent">Drop certificate here</p>
        </div>
      ) : null}
    </div>
  );
}
