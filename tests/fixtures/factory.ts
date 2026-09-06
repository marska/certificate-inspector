/**
 * Builds real X.509 certificates with pkijs so the parser tests run against
 * genuine DER rather than hand-written fixtures. Everything here is test-only.
 */
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';

import { toPem } from '../../src/lib/certificate/encoding';

export interface KeyPairInfo {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

export type KeyAlgorithm = 'RSA' | 'RSA-1024' | 'RSA-SHA1' | 'EC-P256' | 'EC-P384';

export async function generateKeys(algorithm: KeyAlgorithm): Promise<KeyPairInfo> {
  const subtle = globalThis.crypto.subtle;
  if (algorithm.startsWith('RSA')) {
    const modulusLength = algorithm === 'RSA-1024' ? 1024 : 2048;
    // RSASSA-PKCS1-v1_5 takes its digest from the key, not from sign(), so a
    // SHA-1 signature needs a SHA-1 key.
    const pair = (await subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: algorithm === 'RSA-SHA1' ? 'SHA-1' : 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    return { privateKey: pair.privateKey, publicKey: pair.publicKey };
  }

  const namedCurve = algorithm === 'EC-P384' ? 'P-384' : 'P-256';
  const pair = (await subtle.generateKey({ name: 'ECDSA', namedCurve }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  return { privateKey: pair.privateKey, publicKey: pair.publicKey };
}

export interface CertificateOptions {
  subject: Record<string, string>;
  issuer?: Record<string, string>;
  notBefore: Date;
  notAfter: Date;
  serialNumber?: number;
  keys?: KeyPairInfo;
  algorithm?: KeyAlgorithm;
  /** Omit for a self-signed certificate. */
  issuerKeys?: KeyPairInfo;
  ca?: boolean;
  pathLength?: number;
  keyUsage?: number[];
  extendedKeyUsage?: string[];
  san?: { type: number; value: string | Uint8Array }[];
  includeSubjectKeyIdentifier?: boolean;
  /** Explicit AKI bytes; defaults to the issuer's SKI when signing with a CA. */
  authorityKeyIdentifier?: Uint8Array;
  hash?: 'SHA-256' | 'SHA-1' | 'SHA-384';
  /** Corrupt the signature after signing, to test verification failure. */
  breakSignature?: boolean;
}

export interface GeneratedCertificate {
  der: Uint8Array;
  pem: string;
  keys: KeyPairInfo;
  subjectKeyIdentifier: Uint8Array;
  certificate: pkijs.Certificate;
}

const DN_SHORT_TO_OID: Record<string, string> = {
  CN: '2.5.4.3',
  O: '2.5.4.10',
  OU: '2.5.4.11',
  L: '2.5.4.7',
  ST: '2.5.4.8',
  C: '2.5.4.6',
  E: '1.2.840.113549.1.9.1',
};

function fillName(target: pkijs.RelativeDistinguishedNames, values: Record<string, string>) {
  for (const [key, value] of Object.entries(values)) {
    target.typesAndValues.push(
      new pkijs.AttributeTypeAndValue({
        type: DN_SHORT_TO_OID[key] ?? key,
        value:
          key === 'C'
            ? new asn1js.PrintableString({ value })
            : new asn1js.Utf8String({ value }),
      }),
    );
  }
}

/** Packs key usage bit indices (RFC 5280 order) into a BIT STRING. */
function keyUsageBitString(bits: number[]): asn1js.BitString {
  const highest = Math.max(...bits);
  const byteCount = Math.floor(highest / 8) + 1;
  const bytes = new Uint8Array(byteCount);
  for (const bit of bits) bytes[bit >> 3] |= 0x80 >> bit % 8;
  const unusedBits = byteCount * 8 - (highest + 1);
  return new asn1js.BitString({
    valueHex: bytes.buffer as ArrayBuffer,
    unusedBits,
  });
}

export async function createCertificate(
  options: CertificateOptions,
): Promise<GeneratedCertificate> {
  const keys = options.keys ?? (await generateKeys(options.algorithm ?? 'RSA'));
  const issuerKeys = options.issuerKeys ?? keys;

  const certificate = new pkijs.Certificate();
  certificate.version = 2;
  certificate.serialNumber = new asn1js.Integer({
    value: options.serialNumber ?? Math.floor(Math.random() * 1_000_000) + 1,
  });

  fillName(certificate.subject, options.subject);
  fillName(certificate.issuer, options.issuer ?? options.subject);

  certificate.notBefore.value = options.notBefore;
  certificate.notAfter.value = options.notAfter;

  await certificate.subjectPublicKeyInfo.importKey(keys.publicKey);

  const spkiBytes = new Uint8Array(
    certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView,
  );
  const subjectKeyIdentifier = new Uint8Array(
    await globalThis.crypto.subtle.digest('SHA-1', spkiBytes.slice().buffer as ArrayBuffer),
  );

  const extensions: pkijs.Extension[] = [];

  if (options.ca !== undefined || options.pathLength !== undefined) {
    const basicConstraints = new pkijs.BasicConstraints({
      cA: options.ca ?? false,
      ...(options.pathLength !== undefined
        ? { pathLenConstraint: options.pathLength }
        : {}),
    });
    extensions.push(
      new pkijs.Extension({
        extnID: '2.5.29.19',
        critical: true,
        extnValue: basicConstraints.toSchema().toBER(false),
        parsedValue: basicConstraints,
      }),
    );
  }

  if (options.keyUsage?.length) {
    extensions.push(
      new pkijs.Extension({
        extnID: '2.5.29.15',
        critical: true,
        extnValue: keyUsageBitString(options.keyUsage).toBER(false),
      }),
    );
  }

  if (options.extendedKeyUsage?.length) {
    const eku = new pkijs.ExtKeyUsage({ keyPurposes: options.extendedKeyUsage });
    extensions.push(
      new pkijs.Extension({
        extnID: '2.5.29.37',
        critical: false,
        extnValue: eku.toSchema().toBER(false),
        parsedValue: eku,
      }),
    );
  }

  if (options.san?.length) {
    const altName = new pkijs.AltName({
      altNames: options.san.map((entry) =>
        typeof entry.value === 'string'
          ? new pkijs.GeneralName({ type: entry.type as 1 | 2 | 6, value: entry.value })
          : new pkijs.GeneralName({
              type: entry.type as 0 | 3 | 4 | 7 | 8,
              value: new asn1js.OctetString({
                valueHex: entry.value.slice().buffer as ArrayBuffer,
              }),
            }),
      ),
    });
    extensions.push(
      new pkijs.Extension({
        extnID: '2.5.29.17',
        critical: false,
        extnValue: altName.toSchema().toBER(false),
        parsedValue: altName,
      }),
    );
  }

  if (options.includeSubjectKeyIdentifier !== false) {
    extensions.push(
      new pkijs.Extension({
        extnID: '2.5.29.14',
        critical: false,
        extnValue: new asn1js.OctetString({
          valueHex: subjectKeyIdentifier.slice().buffer as ArrayBuffer,
        }).toBER(false),
      }),
    );
  }

  if (options.authorityKeyIdentifier) {
    const aki = new pkijs.AuthorityKeyIdentifier({
      keyIdentifier: new asn1js.OctetString({
        valueHex: options.authorityKeyIdentifier.slice().buffer as ArrayBuffer,
      }),
    });
    extensions.push(
      new pkijs.Extension({
        extnID: '2.5.29.35',
        critical: false,
        extnValue: aki.toSchema().toBER(false),
        parsedValue: aki,
      }),
    );
  }

  if (extensions.length) certificate.extensions = extensions;

  await certificate.sign(issuerKeys.privateKey, options.hash ?? 'SHA-256');

  if (options.breakSignature) {
    const signature = new Uint8Array(
      certificate.signatureValue.valueBlock.valueHexView,
    );
    signature[signature.length - 1] ^= 0xff;
    certificate.signatureValue = new asn1js.BitString({
      valueHex: signature.slice().buffer as ArrayBuffer,
    });
  }

  const der = new Uint8Array(certificate.toSchema(true).toBER(false));

  return {
    der,
    pem: toPem(der),
    keys,
    subjectKeyIdentifier,
    certificate,
  };
}

export const KEY_USAGE = {
  digitalSignature: 0,
  nonRepudiation: 1,
  keyEncipherment: 2,
  dataEncipherment: 3,
  keyAgreement: 4,
  keyCertSign: 5,
  cRLSign: 6,
} as const;

export const EKU = {
  serverAuth: '1.3.6.1.5.5.7.3.1',
  clientAuth: '1.3.6.1.5.5.7.3.2',
} as const;

export const SAN_TYPE = { email: 1, dns: 2, uri: 6, ip: 7 } as const;
