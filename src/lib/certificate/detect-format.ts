import type { InputFormat } from './types';
import { isProbablyBase64 } from './encoding';

export interface PemBlock {
  label: string;
  /** Base64 body with whitespace preserved. */
  body: string;
  kind: 'certificate' | 'private-key' | 'csr' | 'pkcs7' | 'public-key' | 'other';
}

const PEM_BLOCK_RE =
  /-----BEGIN ([A-Z0-9 #._-]+)-----([\s\S]*?)-----END \1-----/g;

const CERTIFICATE_LABELS = new Set([
  'CERTIFICATE',
  'X509 CERTIFICATE',
  'TRUSTED CERTIFICATE',
]);

const CSR_LABELS = new Set(['CERTIFICATE REQUEST', 'NEW CERTIFICATE REQUEST']);

const PKCS7_LABELS = new Set(['PKCS7', 'PKCS #7 SIGNED DATA']);

const PUBLIC_KEY_LABELS = new Set(['PUBLIC KEY', 'RSA PUBLIC KEY']);

export function classifyPemLabel(label: string): PemBlock['kind'] {
  const upper = label.trim().toUpperCase();
  if (CERTIFICATE_LABELS.has(upper)) return 'certificate';
  if (CSR_LABELS.has(upper)) return 'csr';
  if (PKCS7_LABELS.has(upper)) return 'pkcs7';
  if (PUBLIC_KEY_LABELS.has(upper)) return 'public-key';
  if (upper.includes('PRIVATE KEY')) return 'private-key';
  return 'other';
}

/** Extracts every well-formed `-----BEGIN X----- ... -----END X-----` block. */
export function extractPemBlocks(text: string): PemBlock[] {
  const blocks: PemBlock[] = [];
  PEM_BLOCK_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = PEM_BLOCK_RE.exec(text)) !== null) {
    const label = match[1].trim();
    blocks.push({ label, body: match[2], kind: classifyPemLabel(label) });
  }
  return blocks;
}

/** True when the text has a BEGIN header whose matching END footer is absent. */
export function hasUnterminatedPemBlock(text: string): boolean {
  const begins = [...text.matchAll(/-----BEGIN ([A-Z0-9 #._-]+)-----/g)];
  return begins.some(
    (m) => !text.includes(`-----END ${m[1]}-----`),
  );
}

/** True when the text has an END footer but no matching BEGIN header. */
export function hasOrphanPemFooter(text: string): boolean {
  const ends = [...text.matchAll(/-----END ([A-Z0-9 #._-]+)-----/g)];
  return ends.some((m) => !text.includes(`-----BEGIN ${m[1]}-----`));
}

export function looksLikeHex(value: string): boolean {
  const clean = value.replace(/[\s:]/g, '');
  return clean.length >= 32 && clean.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(clean);
}

/** True when a byte buffer plausibly holds text rather than DER. */
export function looksLikeText(bytes: Uint8Array): boolean {
  if (bytes.length === 0) return true;
  if (bytes[0] === 0x30) return false;
  const sample = bytes.subarray(0, Math.min(bytes.length, 512));
  let printable = 0;
  for (const byte of sample) {
    if (byte === 0x09 || byte === 0x0a || byte === 0x0d || (byte >= 0x20 && byte < 0x7f)) {
      printable++;
    }
  }
  return printable / sample.length > 0.9;
}

export interface DerHeader {
  tag: number;
  headerLength: number;
  contentLength: number;
  totalLength: number;
  /** False for indefinite-length or unreadable headers. */
  ok: boolean;
}

/** Reads a single DER TLV header. */
export function readDerHeader(bytes: Uint8Array, offset = 0): DerHeader {
  const fail: DerHeader = {
    tag: bytes[offset] ?? 0,
    headerLength: 0,
    contentLength: 0,
    totalLength: 0,
    ok: false,
  };
  if (bytes.length < offset + 2) return fail;
  const tag = bytes[offset];
  const first = bytes[offset + 1];
  if (first === 0x80) return fail; // indefinite length is not valid DER
  if (first < 0x80) {
    return {
      tag,
      headerLength: 2,
      contentLength: first,
      totalLength: 2 + first,
      ok: true,
    };
  }
  const lengthBytes = first & 0x7f;
  if (lengthBytes > 6 || bytes.length < offset + 2 + lengthBytes) return fail;
  let contentLength = 0;
  for (let i = 0; i < lengthBytes; i++) {
    contentLength = contentLength * 256 + bytes[offset + 2 + i];
  }
  const headerLength = 2 + lengthBytes;
  return {
    tag,
    headerLength,
    contentLength,
    totalLength: headerLength + contentLength,
    ok: true,
  };
}

export type DerShape = 'certificate' | 'pkcs7' | 'pkcs12' | 'unknown';

const OID_PKCS7_SIGNED_DATA = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const OID_PKCS7_DATA = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];

function hasOidAt(bytes: Uint8Array, offset: number, oid: number[]): boolean {
  if (bytes[offset] !== 0x06 || bytes[offset + 1] !== oid.length) return false;
  for (let i = 0; i < oid.length; i++) {
    if (bytes[offset + 2 + i] !== oid[i]) return false;
  }
  return true;
}

/**
 * Distinguishes a bare X.509 certificate from a PKCS#7 bundle or a PKCS#12
 * container by peeking at the first member of the outer SEQUENCE.
 */
export function detectDerShape(bytes: Uint8Array): DerShape {
  const outer = readDerHeader(bytes);
  if (!outer.ok || outer.tag !== 0x30) return 'unknown';
  const inner = outer.headerLength;

  if (hasOidAt(bytes, inner, OID_PKCS7_SIGNED_DATA)) return 'pkcs7';

  // PKCS#12: SEQUENCE { INTEGER version(3), ContentInfo { OID pkcs7-data ... } }
  if (bytes[inner] === 0x02 && bytes[inner + 1] === 0x01 && bytes[inner + 2] === 0x03) {
    const afterVersion = inner + 3;
    const contentInfo = readDerHeader(bytes, afterVersion);
    if (
      contentInfo.ok &&
      contentInfo.tag === 0x30 &&
      hasOidAt(bytes, afterVersion + contentInfo.headerLength, OID_PKCS7_DATA)
    ) {
      return 'pkcs12';
    }
  }

  // X.509 Certificate: SEQUENCE { tbsCertificate SEQUENCE { ... } }
  const tbs = readDerHeader(bytes, inner);
  if (tbs.ok && tbs.tag === 0x30) return 'certificate';

  return 'unknown';
}

/** Coarse classification used for the "Detected input" line in error output. */
export function detectFormat(input: string | Uint8Array): InputFormat {
  if (input instanceof Uint8Array) {
    if (looksLikeText(input)) return detectFormat(new TextDecoder().decode(input));
    const shape = detectDerShape(input);
    if (shape === 'pkcs7') return 'pkcs7';
    if (shape === 'pkcs12') return 'pkcs12';
    return 'der';
  }

  const text = input.trim();
  if (!text) return 'empty';

  const blocks = extractPemBlocks(text);
  if (blocks.length > 0) {
    if (blocks.some((b) => b.kind === 'certificate')) return 'pem';
    if (blocks.some((b) => b.kind === 'pkcs7')) return 'pkcs7';
    if (blocks.some((b) => b.kind === 'csr')) return 'csr';
    if (blocks.some((b) => b.kind === 'private-key')) return 'private-key';
    return 'pem';
  }

  if (text.includes('-----BEGIN')) {
    if (/PRIVATE KEY/i.test(text)) return 'private-key';
    if (/CERTIFICATE REQUEST/i.test(text)) return 'csr';
    return 'pem';
  }

  if (looksLikeHex(text)) return 'hex';
  if (isProbablyBase64(text)) return 'base64-der';
  return 'unknown';
}

export const FORMAT_LABELS: Record<InputFormat, string> = {
  pem: 'PEM',
  der: 'DER (binary)',
  'base64-der': 'Base64',
  'base64-pem': 'Base64-encoded PEM',
  hex: 'Hex',
  pkcs7: 'PKCS#7 bundle',
  pkcs12: 'PKCS#12 / PFX',
  csr: 'Certificate Signing Request',
  'private-key': 'Private key',
  unknown: 'Unrecognised',
  empty: 'Empty',
};
