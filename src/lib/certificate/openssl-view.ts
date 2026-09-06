import { formatOpenSslDate } from './encoding';
import type { ParsedCertificate } from './types';

/**
 * Renders a certificate the way `openssl x509 -text -noout` does.
 *
 * It is a presentation of our own model, so it will not be byte-identical to
 * openssl's output, but the field names, indentation and ordering match so the
 * view is familiar and greppable.
 */
export function opensslView(certificate: ParsedCertificate): string {
  const lines: string[] = [];
  const push = (indent: number, text: string) =>
    lines.push(`${' '.repeat(indent)}${text}`);

  push(0, 'Certificate:');
  push(4, 'Data:');
  push(8, `Version: ${certificate.version} (0x${certificate.version - 1})`);
  push(8, 'Serial Number:');
  push(12, certificate.serialNumber.toLowerCase());
  push(4, `Signature Algorithm: ${certificate.signature.algorithm}`);
  push(8, `Issuer: ${certificate.issuer.oneLine}`);
  push(8, 'Validity');
  push(12, `Not Before: ${formatOpenSslDate(certificate.validity.notBefore)}`);
  push(12, `Not After : ${formatOpenSslDate(certificate.validity.notAfter)}`);
  push(8, `Subject: ${certificate.subject.oneLine}`);
  push(8, 'Subject Public Key Info:');
  push(12, `Public Key Algorithm: ${publicKeyAlgorithmName(certificate)}`);

  const { publicKey } = certificate;
  if (publicKey.algorithm.startsWith('RSA')) {
    push(16, `Public-Key: (${publicKey.size ?? '?'} bit)`);
    if (publicKey.modulusHex) {
      push(16, 'Modulus:');
      for (const line of chunkHex(publicKey.modulusHex, 15)) push(20, line);
    }
    push(
      16,
      `Exponent: ${publicKey.exponent ?? '?'} (0x${(publicKey.exponent ?? 0).toString(16)})`,
    );
  } else if (publicKey.algorithm === 'ECDSA') {
    push(16, `Public-Key: (${publicKey.size ?? '?'} bit)`);
    push(16, 'pub:');
    for (const line of chunkHex(publicKey.keyHex, 15)) push(20, line);
    push(16, `ASN1 OID: ${publicKey.curve ?? publicKey.curveOid ?? 'unknown'}`);
    if (publicKey.curveOid) push(16, `NIST CURVE: ${nistName(publicKey.curveOid)}`);
  } else {
    push(16, `Public-Key: (${publicKey.size ?? '?'} bit)`);
    push(16, 'pub:');
    for (const line of chunkHex(publicKey.keyHex, 15)) push(20, line);
  }

  if (certificate.extensions.length > 0) {
    push(8, 'X509v3 extensions:');
    for (const extension of certificate.extensions) {
      push(
        12,
        `${extensionTitle(extension.oid, extension.name)}: ${
          extension.critical ? 'critical' : ''
        }`.trimEnd(),
      );
      for (const line of extension.value.split('\n')) push(16, line);
    }
  }

  push(4, `Signature Algorithm: ${certificate.signature.algorithm}`);
  for (const line of chunkHex(certificate.signature.valueHex, 18)) push(9, line);

  return lines.join('\n');
}

/** The command that produces this view, ready to copy. */
export const OPENSSL_COMMAND = 'openssl x509 -in certificate.crt -text -noout';

function publicKeyAlgorithmName(certificate: ParsedCertificate): string {
  switch (certificate.publicKey.algorithm) {
    case 'RSA':
      return 'rsaEncryption';
    case 'ECDSA':
      return 'id-ecPublicKey';
    case 'DSA':
      return 'dsaEncryption';
    default:
      return certificate.publicKey.algorithm;
  }
}

function extensionTitle(oid: string, name: string): string {
  // openssl prefixes standard v3 extensions with "X509v3".
  return oid.startsWith('2.5.29.') ? `X509v3 ${name}` : name;
}

function nistName(curveOid: string): string {
  const map: Record<string, string> = {
    '1.2.840.10045.3.1.7': 'P-256',
    '1.3.132.0.34': 'P-384',
    '1.3.132.0.35': 'P-521',
    '1.3.132.0.33': 'P-224',
    '1.2.840.10045.3.1.1': 'P-192',
  };
  return map[curveOid] ?? 'unknown';
}

function chunkHex(colonHex: string, perLine: number): string[] {
  const bytes = colonHex.toLowerCase().split(':').filter(Boolean);
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += perLine) {
    lines.push(`${bytes.slice(i, i + perLine).join(':')}${i + perLine < bytes.length ? ':' : ''}`);
  }
  return lines;
}
