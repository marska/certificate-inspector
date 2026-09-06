import { Certificate, ContentInfo, SignedData } from 'pkijs';

import type {
  DecodeIssue,
  DecodeIssueCode,
  DecodeResult,
  DecodedBlock,
  InputFormat,
} from './types';
import {
  base64ToBytes,
  invalidBase64Characters,
  isProbablyBase64,
  toPem,
} from './encoding';
import {
  FORMAT_LABELS,
  detectDerShape,
  extractPemBlocks,
  hasOrphanPemFooter,
  hasUnterminatedPemBlock,
  looksLikeHex,
  looksLikeText,
  readDerHeader,
} from './detect-format';

const MAX_BASE64_DEPTH = 3;

class Decoder {
  readonly blocks: DecodedBlock[] = [];
  readonly issues: DecodeIssue[] = [];
  containsPrivateKey = false;
  format: InputFormat = 'unknown';

  issue(
    severity: DecodeIssue['severity'],
    code: DecodeIssueCode,
    message: string,
    detail?: string,
  ) {
    const duplicate = this.issues.some(
      (existing) => existing.code === code && existing.message === message,
    );
    if (!duplicate) this.issues.push({ severity, code, message, detail });
  }

  addDer(der: Uint8Array, via: InputFormat) {
    this.blocks.push({ der, pem: toPem(der), via });
  }
}

/**
 * Turns arbitrary user input into a list of DER certificate blocks.
 *
 * The pipeline is: detect format → unwrap (base64 / hex / PEM, recursively) →
 * split into DER blocks → sanity-check each block. Every failure mode produces
 * a specific issue rather than a generic "invalid certificate".
 */
export function decodeInput(input: string | Uint8Array): DecodeResult {
  const decoder = new Decoder();

  if (input instanceof Uint8Array) {
    if (input.length === 0) {
      decoder.format = 'empty';
    } else if (looksLikeText(input)) {
      decodeText(new TextDecoder().decode(input), decoder, 0);
    } else {
      decoder.format = 'der';
      decodeDer(input, decoder, 'der');
    }
  } else {
    decodeText(input, decoder, 0);
  }

  if (
    decoder.blocks.length === 0 &&
    decoder.format !== 'empty' &&
    !decoder.issues.some((i) => i.severity === 'error')
  ) {
    decoder.issue(
      'error',
      'NO_CERTIFICATE_FOUND',
      'No X.509 certificate found.',
      'The input was read successfully but does not contain a certificate structure.',
    );
  }

  return {
    blocks: decoder.blocks,
    detectedFormat: decoder.format,
    detectedFormatLabel: FORMAT_LABELS[decoder.format],
    issues: decoder.issues,
    containsPrivateKey: decoder.containsPrivateKey,
  };
}

function decodeText(raw: string, decoder: Decoder, depth: number): void {
  const text = raw.replace(/\r\n/g, '\n').trim();

  if (!text) {
    decoder.format = 'empty';
    return;
  }

  const pemBlocks = extractPemBlocks(text);

  if (pemBlocks.length > 0) {
    if (depth === 0) decoder.format = 'pem';
    for (const block of pemBlocks) {
      switch (block.kind) {
        case 'certificate': {
          const der = decodeBase64Body(block.body, decoder, 'PEM block');
          if (der) decodeDer(der, decoder, depth === 0 ? 'pem' : 'base64-pem');
          break;
        }
        case 'pkcs7': {
          const der = decodeBase64Body(block.body, decoder, 'PKCS#7 block');
          if (der) decodeDer(der, decoder, 'pkcs7');
          break;
        }
        case 'private-key': {
          decoder.containsPrivateKey = true;
          decoder.issue(
            'warning',
            'PRIVATE_KEY_DETECTED',
            'Private key detected in the input.',
            `A "${block.label}" block was found. It was neither uploaded nor stored — ` +
              'but you should avoid pasting private keys into any online tool.',
          );
          break;
        }
        case 'csr': {
          decoder.issue(
            'warning',
            'CSR_DETECTED',
            'Certificate Signing Request detected.',
            'CSR inspection is not part of this version. Paste an issued certificate instead.',
          );
          break;
        }
        case 'public-key': {
          decoder.issue(
            'info',
            'NO_CERTIFICATE_FOUND',
            'A bare public key was found, not a certificate.',
            `The "${block.label}" block holds only a key, so there is nothing to inspect ` +
              '(no subject, issuer or validity).',
          );
          break;
        }
        default: {
          decoder.issue(
            'info',
            'NO_CERTIFICATE_FOUND',
            `Unsupported PEM block: ${block.label}.`,
            'Only certificate blocks are decoded.',
          );
        }
      }
    }
    return;
  }

  // No complete PEM block — work out why, or unwrap another layer.
  if (hasUnterminatedPemBlock(text)) {
    const label = text.match(/-----BEGIN ([A-Z0-9 #._-]+)-----/)?.[1] ?? 'CERTIFICATE';
    decoder.format = 'pem';
    decoder.issue(
      'error',
      'PEM_MISSING_END',
      `PEM block is missing END ${label}.`,
      'The closing footer was not found. Make sure you copied the whole block, ' +
        `including the final "-----END ${label}-----" line.`,
    );
    return;
  }

  if (hasOrphanPemFooter(text)) {
    decoder.format = 'pem';
    decoder.issue(
      'error',
      'PEM_MISSING_BEGIN',
      'PEM block is missing the BEGIN header.',
      'An END footer was found without a matching BEGIN header.',
    );
    return;
  }

  if (looksLikeHex(text)) {
    if (depth === 0) decoder.format = 'hex';
    const clean = text.replace(/[\s:]/g, '');
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    decodeDer(bytes, decoder, 'hex');
    return;
  }

  const invalidChars = invalidBase64Characters(text);
  if (invalidChars.length > 0) {
    if (depth === 0) decoder.format = 'unknown';
    // Only call it damaged Base64 when it mostly looks like Base64 — otherwise
    // the user pasted something else entirely and deserves a different message.
    if (looksLikeDamagedBase64(text)) {
      decoder.issue(
        'error',
        'INVALID_BASE64',
        'Invalid Base64 characters detected.',
        `The input is not a PEM block and contains characters that cannot appear in ` +
          `Base64: ${invalidChars.slice(0, 8).map((c) => JSON.stringify(c)).join(', ')}.`,
      );
    } else {
      decoder.issue(
        'error',
        'NO_CERTIFICATE_FOUND',
        'No X.509 certificate found.',
        'The input does not look like PEM, Base64 or hex certificate data.',
      );
    }
    return;
  }

  if (!isProbablyBase64(text)) {
    if (depth === 0) decoder.format = 'unknown';
    decoder.issue(
      'error',
      'NO_CERTIFICATE_FOUND',
      'No X.509 certificate found.',
      'The input does not look like PEM, Base64 or hex certificate data.',
    );
    return;
  }

  const clean = text.replace(/\s+/g, '');
  if (clean.length % 4 !== 0) {
    decoder.issue(
      'warning',
      'INCOMPLETE_BASE64',
      'The Base64 data appears to be incomplete.',
      `Its length (${clean.length} characters) is not a multiple of 4, which usually ` +
        'means the value was truncated when it was copied.',
    );
  }

  let bytes: Uint8Array;
  try {
    bytes = base64ToBytes(clean);
  } catch {
    decoder.issue(
      'error',
      'INVALID_BASE64',
      'Invalid Base64 characters detected.',
      'The Base64 payload could not be decoded.',
    );
    return;
  }

  // Base64 that decodes to text is very often a base64-wrapped PEM file.
  if (looksLikeText(bytes)) {
    const inner = new TextDecoder().decode(bytes);
    if (inner.includes('-----BEGIN') && depth < MAX_BASE64_DEPTH) {
      if (depth === 0) decoder.format = 'base64-pem';
      decodeText(inner, decoder, depth + 1);
      return;
    }
    if (depth === 0) decoder.format = 'base64-der';
    decoder.issue(
      'error',
      'NOT_DER',
      'The Base64 data does not contain a certificate.',
      'It decodes to text rather than to a DER structure.',
    );
    return;
  }

  if (depth === 0) decoder.format = 'base64-der';
  decodeDer(bytes, decoder, 'base64-der');
}

/**
 * True when the input reads as Base64 that got mangled, rather than as ordinary
 * text that happens to contain a few letters.
 */
function looksLikeDamagedBase64(text: string): boolean {
  const clean = text.replace(/\s+/g, '');
  if (clean.length < 40) return false;
  const valid = clean.replace(/[^A-Za-z0-9+/=]/g, '').length;
  return valid / clean.length >= 0.85;
}

/** Decodes a PEM body, reporting bad characters precisely. */
function decodeBase64Body(
  body: string,
  decoder: Decoder,
  context: string,
): Uint8Array | undefined {
  const invalid = invalidBase64Characters(body);
  if (invalid.length > 0) {
    decoder.issue(
      'error',
      'INVALID_BASE64',
      'Invalid Base64 characters detected.',
      `The ${context} contains characters that cannot appear in Base64: ` +
        `${invalid.slice(0, 8).map((c) => JSON.stringify(c)).join(', ')}.`,
    );
    return undefined;
  }
  const clean = body.replace(/\s+/g, '');
  if (clean.length === 0) {
    decoder.issue('error', 'PARSE_FAILED', `The ${context} is empty.`);
    return undefined;
  }
  if (clean.length % 4 !== 0) {
    decoder.issue(
      'warning',
      'INCOMPLETE_BASE64',
      'The Base64 data appears to be incomplete.',
      `The ${context} has a length that is not a multiple of 4, which usually means ` +
        'part of it is missing.',
    );
  }
  try {
    return base64ToBytes(clean);
  } catch {
    decoder.issue('error', 'INVALID_BASE64', 'Invalid Base64 characters detected.');
    return undefined;
  }
}

/**
 * Splits a DER buffer into certificate blocks. Handles bare certificates,
 * several certificates concatenated together, and PKCS#7 bundles.
 */
function decodeDer(bytes: Uint8Array, decoder: Decoder, via: InputFormat): void {
  let offset = 0;
  let guard = 0;

  while (offset < bytes.length && guard++ < 64) {
    const remaining = bytes.subarray(offset);
    // Tolerate trailing NUL padding produced by some exporters.
    if (remaining.every((b) => b === 0)) return;

    const header = readDerHeader(remaining);
    if (!header.ok || header.tag !== 0x30) {
      decoder.issue(
        'error',
        'NOT_DER',
        'The data is not a valid DER structure.',
        'A DER certificate must start with a SEQUENCE (byte 0x30). ' +
          `Found 0x${(remaining[0] ?? 0).toString(16).padStart(2, '0')} instead.`,
      );
      return;
    }

    if (header.totalLength > remaining.length) {
      decoder.issue(
        'error',
        'TRUNCATED_DER',
        'The certificate appears truncated.',
        `The DER header declares ${header.totalLength} bytes but only ` +
          `${remaining.length} are present — ${header.totalLength - remaining.length} ` +
          'bytes are missing.',
      );
      return;
    }

    const der = remaining.subarray(0, header.totalLength);
    const shape = detectDerShape(der);

    if (shape === 'pkcs12') {
      decoder.format = 'pkcs12';
      decoder.issue(
        'error',
        'PKCS12_UNSUPPORTED',
        'PKCS#12 / PFX containers are not supported yet.',
        'This file is an encrypted key store. Export the certificate first, for ' +
          'example with: openssl pkcs12 -in store.pfx -clcerts -nokeys -out cert.pem',
      );
      return;
    }

    if (shape === 'pkcs7') {
      extractPkcs7(der, decoder);
    } else if (shape === 'certificate') {
      decoder.addDer(der, via);
    } else {
      decoder.issue(
        'error',
        'NOT_DER',
        'The DER structure is not an X.509 certificate.',
        'The outer SEQUENCE does not contain a tbsCertificate.',
      );
      return;
    }

    offset += header.totalLength;
  }
}

function extractPkcs7(der: Uint8Array, decoder: Decoder): void {
  if (decoder.format !== 'pkcs12') decoder.format = 'pkcs7';
  try {
    const contentInfo = ContentInfo.fromBER(copy(der));
    const signedData = new SignedData({ schema: contentInfo.content });
    const certificates = (signedData.certificates ?? []).filter(
      (candidate): candidate is Certificate => candidate instanceof Certificate,
    );
    if (certificates.length === 0) {
      decoder.issue(
        'error',
        'NO_CERTIFICATE_FOUND',
        'The PKCS#7 bundle contains no certificates.',
      );
      return;
    }
    for (const certificate of certificates) {
      decoder.addDer(new Uint8Array(certificate.toSchema().toBER(false)), 'pkcs7');
    }
  } catch (error) {
    decoder.issue(
      'error',
      'PARSE_FAILED',
      'Unable to read the PKCS#7 bundle.',
      error instanceof Error ? error.message : undefined,
    );
  }
}

/** pkijs mutates nothing, but it wants a standalone ArrayBuffer. */
function copy(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}
