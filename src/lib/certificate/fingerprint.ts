import { toColonHex } from './encoding';

export type DigestAlgorithm = 'SHA-256' | 'SHA-1' | 'SHA-384' | 'SHA-512';

function subtle(): SubtleCrypto {
  const crypto = globalThis.crypto;
  if (!crypto?.subtle) {
    throw new Error(
      'WebCrypto is unavailable. Certificate Inspector needs a secure context (https or localhost).',
    );
  }
  return crypto.subtle;
}

export async function digest(
  algorithm: DigestAlgorithm,
  data: Uint8Array,
): Promise<Uint8Array> {
  const buffer = await subtle().digest(algorithm, data.slice().buffer as ArrayBuffer);
  return new Uint8Array(buffer);
}

/** Colon-separated uppercase hex, the form every CA console shows. */
export async function fingerprint(
  algorithm: DigestAlgorithm,
  data: Uint8Array,
): Promise<string> {
  return toColonHex(await digest(algorithm, data));
}

export async function certificateFingerprints(der: Uint8Array): Promise<{
  sha256: string;
  sha1: string;
}> {
  const [sha256, sha1] = await Promise.all([
    fingerprint('SHA-256', der),
    fingerprint('SHA-1', der),
  ]);
  return { sha256, sha1 };
}
