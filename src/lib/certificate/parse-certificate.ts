import * as asn1js from 'asn1js';
import { Certificate, RSASSAPSSParams } from 'pkijs';

import {
  CURVE_OIDS,
  HASH_OIDS,
  PUBLIC_KEY_OIDS,
  SIGNATURE_OIDS,
  WEAK_HASHES,
} from './oids';
import { canonicalDn, dnValue, parseDistinguishedName } from './names';
import { parseExtensions } from './parse-extensions';
import { certificateFingerprints } from './fingerprint';
import { bytesToDecimal, toHex, toPem } from './encoding';
import type {
  CertificateValidity,
  DistinguishedName,
  ParsedCertificate,
  PublicKeyInfo,
  SignatureInfo,
} from './types';

export const MS_PER_DAY = 86_400_000;
/** A certificate inside this window is reported as "expiring soon". */
export const EXPIRY_WARNING_DAYS = 30;

export interface ParseOptions {
  /** Injectable clock, so validity tests are deterministic. */
  now?: Date;
}

/** Thrown when a DER block is not a certificate we can read. */
export class CertificateParseError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = 'CertificateParseError';
  }
}

export async function parseCertificate(
  der: Uint8Array,
  options: ParseOptions = {},
): Promise<ParsedCertificate> {
  let pki: Certificate;
  try {
    pki = Certificate.fromBER(der.slice().buffer as ArrayBuffer);
  } catch (error) {
    throw new CertificateParseError(
      'Unable to parse certificate: the ASN.1 structure is not a valid X.509 certificate.',
      error,
    );
  }
  return buildParsedCertificate(pki, der, options);
}

/** Same as {@link parseCertificate} but for an already-decoded pkijs object. */
export async function buildParsedCertificate(
  pki: Certificate,
  der: Uint8Array,
  options: ParseOptions = {},
): Promise<ParsedCertificate> {
  const now = options.now ?? new Date();

  const subject = parseDistinguishedName(pki.subject);
  const issuer = parseDistinguishedName(pki.issuer);
  const extensions = parseExtensions(pki.extensions);

  const serialBytes = new Uint8Array(pki.serialNumber.valueBlock.valueHexView);
  const validity = buildValidity(pki.notBefore.value, pki.notAfter.value, now);
  const fingerprints = await certificateFingerprints(der);

  const commonName = dnValue(subject, 'CN');
  const isSelfSigned = detectSelfSigned(
    subject,
    issuer,
    extensions.subjectKeyIdentifier,
    extensions.authorityKeyIdentifier,
  );

  return {
    id: fingerprints.sha256.replace(/:/g, ''),
    subject,
    issuer,
    commonName,
    serialNumber: toHex(serialBytes, ':'),
    serialNumberDecimal: bytesToDecimal(serialBytes),
    version: pki.version + 1,
    validity,
    subjectAlternativeNames: extensions.subjectAlternativeNames,
    publicKey: buildPublicKey(pki),
    signature: buildSignature(pki),
    isCA: extensions.basicConstraints.ca,
    isSelfSigned,
    basicConstraints: extensions.basicConstraints,
    keyUsage: extensions.keyUsage,
    keyUsageNames: extensions.keyUsageNames,
    extendedKeyUsage: extensions.extendedKeyUsage,
    subjectKeyIdentifier: extensions.subjectKeyIdentifier,
    authorityKeyIdentifier: extensions.authorityKeyIdentifier,
    crlDistributionPoints: extensions.crlDistributionPoints,
    ocspUrls: extensions.ocspUrls,
    caIssuerUrls: extensions.caIssuerUrls,
    authorityInfoAccess: extensions.authorityInfoAccess,
    fingerprints,
    extensions: extensions.list,
    pem: toPem(der),
    der,
    label: buildLabel(commonName, subject, extensions.subjectAlternativeNames, serialBytes),
  };
}

/** Parses many DER blocks, keeping per-block failures out of the happy path. */
export async function parseCertificates(
  blocks: Uint8Array[],
  options: ParseOptions = {},
): Promise<{ certificates: ParsedCertificate[]; errors: CertificateParseError[] }> {
  const certificates: ParsedCertificate[] = [];
  const errors: CertificateParseError[] = [];

  for (const der of blocks) {
    try {
      certificates.push(await parseCertificate(der, options));
    } catch (error) {
      errors.push(
        error instanceof CertificateParseError
          ? error
          : new CertificateParseError('Unable to parse certificate.', error),
      );
    }
  }

  return { certificates, errors };
}

export function buildValidity(
  notBefore: Date,
  notAfter: Date,
  now: Date,
): CertificateValidity {
  const remainingMs = notAfter.getTime() - now.getTime();
  const daysRemaining =
    remainingMs >= 0
      ? Math.ceil(remainingMs / MS_PER_DAY)
      : -Math.ceil(-remainingMs / MS_PER_DAY);

  const periodMs = notAfter.getTime() - notBefore.getTime();
  const periodDays = Math.max(0, Math.round(periodMs / MS_PER_DAY));

  let status: CertificateValidity['status'];
  if (now < notBefore) status = 'not-yet-valid';
  else if (remainingMs < 0) status = 'expired';
  else if (daysRemaining <= EXPIRY_WARNING_DAYS) status = 'expiring-soon';
  else status = 'valid';

  const elapsed = periodMs > 0 ? (now.getTime() - notBefore.getTime()) / periodMs : 1;

  return {
    notBefore,
    notAfter,
    status,
    daysRemaining,
    periodDays,
    elapsedFraction: Math.min(1, Math.max(0, elapsed)),
  };
}

/**
 * Subject == issuer is the necessary condition; a matching AKI/SKI pair is
 * required too when both are present, which rules out cross-signed lookalikes.
 * Whether the self-signature actually verifies is checked by the chain
 * validator, not here.
 */
function detectSelfSigned(
  subject: DistinguishedName,
  issuer: DistinguishedName,
  ski?: string,
  aki?: string,
): boolean {
  if (canonicalDn(subject) !== canonicalDn(issuer)) return false;
  if (ski && aki) return ski === aki;
  return true;
}

function buildPublicKey(pki: Certificate): PublicKeyInfo {
  const spki = pki.subjectPublicKeyInfo;
  const oid = spki.algorithm.algorithmId;
  const algorithm = PUBLIC_KEY_OIDS[oid] ?? oid;
  const keyBytes = new Uint8Array(spki.subjectPublicKey.valueBlock.valueHexView);
  const info: PublicKeyInfo = { algorithm, oid, keyHex: toHex(keyBytes, ':') };

  if (algorithm === 'RSA' || algorithm === 'RSASSA-PSS') {
    const rsa = readRsaKey(keyBytes);
    if (rsa) {
      info.size = rsa.size;
      info.exponent = rsa.exponent;
      info.modulusHex = rsa.modulusHex;
    }
    return info;
  }

  if (algorithm === 'ECDSA') {
    const params = spki.algorithm.algorithmParams;
    if (params instanceof asn1js.ObjectIdentifier) {
      const curveOid = params.valueBlock.toString();
      const curve = CURVE_OIDS[curveOid];
      info.curveOid = curveOid;
      info.curve = curve?.name ?? curveOid;
      info.size = curve?.size ?? uncompressedPointSize(keyBytes);
    } else {
      info.size = uncompressedPointSize(keyBytes);
    }
    return info;
  }

  if (algorithm === 'Ed25519' || algorithm === 'X25519') info.size = 256;
  else if (algorithm === 'Ed448') info.size = 456;
  else if (algorithm === 'X448') info.size = 448;
  else if (algorithm === 'DSA') {
    const params = spki.algorithm.algorithmParams;
    const p = (params as asn1js.Sequence | undefined)?.valueBlock?.value?.[0];
    if (p instanceof asn1js.Integer) {
      info.size = stripLeadingZero(new Uint8Array(p.valueBlock.valueHexView)).length * 8;
    }
  }

  return info;
}

function readRsaKey(
  keyBytes: Uint8Array,
): { size: number; exponent: number; modulusHex: string } | undefined {
  const parsed = asn1js.fromBER(keyBytes.slice().buffer as ArrayBuffer);
  if (parsed.offset === -1) return undefined;
  const sequence = parsed.result as asn1js.Sequence;
  const [modulus, exponent] = (sequence.valueBlock?.value ?? []) as asn1js.Integer[];
  if (!(modulus instanceof asn1js.Integer)) return undefined;

  const rawModulus = new Uint8Array(modulus.valueBlock.valueHexView);
  const modulusBytes = stripLeadingZero(rawModulus);
  let exponentValue = 0;
  if (exponent instanceof asn1js.Integer) {
    for (const byte of new Uint8Array(exponent.valueBlock.valueHexView)) {
      exponentValue = exponentValue * 256 + byte;
    }
  }
  return {
    size: modulusBytes.length * 8,
    exponent: exponentValue,
    modulusHex: toHex(rawModulus, ':'),
  };
}

/** For an uncompressed EC point (0x04 || X || Y), the field size is |X| * 8. */
function uncompressedPointSize(keyBytes: Uint8Array): number | undefined {
  if (keyBytes.length < 3 || keyBytes[0] !== 0x04) return undefined;
  return ((keyBytes.length - 1) / 2) * 8;
}

function stripLeadingZero(bytes: Uint8Array): Uint8Array {
  return bytes.length > 1 && bytes[0] === 0x00 ? bytes.subarray(1) : bytes;
}

function buildSignature(pki: Certificate): SignatureInfo {
  const oid = pki.signatureAlgorithm.algorithmId;
  const known = SIGNATURE_OIDS[oid];
  let algorithm = known?.name ?? oid;
  let hashAlgorithm = known?.hash;

  if (oid === '1.2.840.113549.1.1.10') {
    hashAlgorithm = readPssHash(pki) ?? 'SHA-1';
    algorithm = `RSASSA-PSS (${hashAlgorithm})`;
  }

  const weak = hashAlgorithm ? WEAK_HASHES.has(hashAlgorithm) : false;

  return {
    algorithm,
    oid,
    hashAlgorithm,
    weak,
    weakReason: weak
      ? `${hashAlgorithm} is considered deprecated for certificate signatures: ` +
        'practical collision attacks exist and public CAs no longer issue with it.'
      : undefined,
    valueHex: toHex(new Uint8Array(pki.signatureValue.valueBlock.valueHexView), ':'),
  };
}

/** RSASSA-PSS carries its digest in the algorithm parameters; the default is SHA-1. */
function readPssHash(pki: Certificate): string | undefined {
  const params = pki.signatureAlgorithm.algorithmParams;
  if (!params) return undefined;
  try {
    const pss = new RSASSAPSSParams({ schema: params });
    const hashOid = pss.hashAlgorithm?.algorithmId;
    return hashOid ? (HASH_OIDS[hashOid] ?? hashOid) : undefined;
  } catch {
    return undefined;
  }
}

function buildLabel(
  commonName: string | undefined,
  subject: DistinguishedName,
  sans: ParsedCertificate['subjectAlternativeNames'],
  serial: Uint8Array,
): string {
  if (commonName) return commonName;
  const dns = sans.find((san) => san.type === 'dns');
  if (dns) return dns.value;
  const organisation = dnValue(subject, 'O') ?? dnValue(subject, 'OU');
  if (organisation) return organisation;
  if (subject.oneLine) return subject.oneLine;
  return `Serial ${toHex(serial, ':')}`;
}
