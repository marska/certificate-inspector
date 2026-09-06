/**
 * Unified certificate model.
 *
 * Nothing outside `lib/certificate` should ever touch a pkijs/asn1js object:
 * the parser translates the library output into the types below, and the UI
 * only ever consumes these.
 */

export interface DistinguishedNameAttribute {
  /** Short name where one exists (CN, O, OU, L, ST, C, E, ...). */
  shortName: string;
  /** Human readable name ("Common Name"). */
  longName: string;
  oid: string;
  value: string;
}

export interface DistinguishedName {
  attributes: DistinguishedNameAttribute[];
  /** One-line RFC 4514-ish rendering, e.g. `CN=api.example.com, O=Example, C=PL`. */
  oneLine: string;
  /** Multi-line rendering, one attribute per line. */
  multiLine: string;
}

export type ValidityStatus =
  | 'valid'
  | 'expiring-soon'
  | 'expired'
  | 'not-yet-valid';

export interface CertificateValidity {
  notBefore: Date;
  notAfter: Date;
  status: ValidityStatus;
  /** Days until `notAfter`. Negative once expired. */
  daysRemaining: number;
  /** Total length of the validity window in days. */
  periodDays: number;
  /** 0..1 — how much of the validity window has elapsed. */
  elapsedFraction: number;
}

export type SanType = 'dns' | 'ip' | 'uri' | 'email' | 'dirname' | 'other';

export interface SubjectAlternativeName {
  type: SanType;
  /** Label shown in the UI: DNS, IP, URI, Email, Directory Name, Other. */
  label: string;
  value: string;
}

export interface PublicKeyInfo {
  /** Friendly algorithm name: RSA, ECDSA, Ed25519, ... */
  algorithm: string;
  /** Key size in bits, when determinable. */
  size?: number;
  /** Named curve for EC keys, e.g. `prime256v1 / secp256r1`. */
  curve?: string;
  /** Curve OID for EC keys. */
  curveOid?: string;
  /** RSA public exponent. */
  exponent?: number;
  oid?: string;
  /** Hex of the raw SubjectPublicKey bit string. */
  keyHex: string;
  /** RSA modulus, colon-hex, including the leading 00 openssl prints. */
  modulusHex?: string;
}

export interface SignatureInfo {
  /** e.g. `sha256WithRSAEncryption`. */
  algorithm: string;
  oid?: string;
  /** e.g. `SHA-256`. */
  hashAlgorithm?: string;
  /** True for MD2/MD5/SHA-1 based signatures. */
  weak: boolean;
  /** Why the algorithm is considered weak, when it is. */
  weakReason?: string;
  /** Hex of the signature value. */
  valueHex: string;
}

export interface KeyUsageFlag {
  name: string;
  enabled: boolean;
}

export interface ExtendedKeyUsagePurpose {
  name: string;
  oid: string;
  /** False when the OID is unknown to us and only the number is shown. */
  known: boolean;
}

export interface BasicConstraints {
  present: boolean;
  ca: boolean;
  pathLength?: number;
  critical: boolean;
}

export interface AccessDescriptionEntry {
  method: string;
  methodOid: string;
  location: string;
}

export interface CertificateExtension {
  oid: string;
  name: string;
  critical: boolean;
  /** Rendered value, one logical entry per line. */
  value: string;
  /** True when we could not decode the extension and fell back to hex. */
  raw: boolean;
}

export interface Asn1Node {
  name: string;
  type: string;
  value?: string;
  offset: number;
  length: number;
  children?: Asn1Node[];
}

export interface ParsedCertificate {
  /** Stable id — the SHA-256 fingerprint without separators. */
  id: string;

  subject: DistinguishedName;
  issuer: DistinguishedName;

  commonName?: string;
  serialNumber: string;
  /** Serial as a decimal string (useful for some CA portals). */
  serialNumberDecimal: string;
  version: number;

  validity: CertificateValidity;

  subjectAlternativeNames: SubjectAlternativeName[];

  publicKey: PublicKeyInfo;
  signature: SignatureInfo;

  isCA: boolean;
  isSelfSigned: boolean;
  basicConstraints: BasicConstraints;

  keyUsage: KeyUsageFlag[];
  /** Only the enabled key usages, as plain strings (spec model). */
  keyUsageNames: string[];
  extendedKeyUsage: ExtendedKeyUsagePurpose[];

  subjectKeyIdentifier?: string;
  authorityKeyIdentifier?: string;
  crlDistributionPoints: string[];
  ocspUrls: string[];
  caIssuerUrls: string[];
  authorityInfoAccess: AccessDescriptionEntry[];

  fingerprints: {
    sha256: string;
    sha1: string;
    md5?: string;
  };

  extensions: CertificateExtension[];

  pem: string;
  der: Uint8Array;

  /** Best-effort short label for chain nodes and tabs. */
  label: string;
  /** leaf / intermediate / root, filled in by the chain builder. */
  role?: CertificateRole;
}

export type CertificateRole = 'leaf' | 'intermediate' | 'root' | 'unknown';

/* ------------------------------------------------------------------ */
/* Input decoding                                                      */
/* ------------------------------------------------------------------ */

export type InputFormat =
  | 'pem'
  | 'der'
  | 'base64-der'
  | 'base64-pem'
  | 'hex'
  | 'pkcs7'
  | 'pkcs12'
  | 'csr'
  | 'private-key'
  | 'unknown'
  | 'empty';

export interface DecodedBlock {
  der: Uint8Array;
  pem: string;
  /** How this block was recovered from the input. */
  via: InputFormat;
}

export type DecodeIssueCode =
  | 'PRIVATE_KEY_DETECTED'
  | 'CSR_DETECTED'
  | 'PKCS7_UNSUPPORTED'
  | 'PKCS12_UNSUPPORTED'
  | 'PEM_MISSING_END'
  | 'PEM_MISSING_BEGIN'
  | 'INVALID_BASE64'
  | 'INCOMPLETE_BASE64'
  | 'TRUNCATED_DER'
  | 'NOT_DER'
  | 'NO_CERTIFICATE_FOUND'
  | 'PARSE_FAILED';

export interface DecodeIssue {
  severity: 'info' | 'warning' | 'error';
  code: DecodeIssueCode;
  /** Short headline. */
  message: string;
  /** Longer explanation of the likely cause / what to do. */
  detail?: string;
}

export interface DecodeResult {
  blocks: DecodedBlock[];
  detectedFormat: InputFormat;
  /** Human readable format name for the UI. */
  detectedFormatLabel: string;
  issues: DecodeIssue[];
  /** True when the input contained a private key block. */
  containsPrivateKey: boolean;
}

/* ------------------------------------------------------------------ */
/* Chain                                                               */
/* ------------------------------------------------------------------ */

export type LinkCheckStatus = 'ok' | 'fail' | 'unknown' | 'skipped';

export interface LinkCheck {
  label: string;
  status: LinkCheckStatus;
  detail?: string;
}

export interface ChainLink {
  /** Certificate being verified. */
  subjectId: string;
  subjectLabel: string;
  /** The presumed issuer, when present in the input. */
  issuerId?: string;
  issuerLabel?: string;
  checks: LinkCheck[];
}

export type ChainStatus = 'valid' | 'invalid' | 'incomplete' | 'unknown';

export type ChainIssueCode =
  | 'CERT_EXPIRED'
  | 'CERT_EXPIRING_SOON'
  | 'CERT_NOT_YET_VALID'
  | 'CHAIN_INCOMPLETE'
  | 'ISSUER_NOT_FOUND'
  | 'SIGNATURE_INVALID'
  | 'SIGNATURE_UNVERIFIABLE'
  | 'SIGNATURE_OK'
  | 'WEAK_SIGNATURE'
  | 'SELF_SIGNED_LEAF'
  | 'DUPLICATE_CERTIFICATE'
  | 'INVALID_CA_CONSTRAINT'
  | 'LEAF_IS_CA'
  | 'ROOT_INCLUDED'
  | 'WRONG_ORDER'
  | 'UNRELATED_CERTIFICATE'
  | 'CHAIN_COMPLETE'
  | 'CERT_VALID';

export interface ChainIssue {
  severity: 'info' | 'warning' | 'error' | 'success';
  certificateId?: string;
  code: ChainIssueCode;
  message: string;
  detail?: string;
}

export interface CertificateChain {
  /** Every certificate found in the input, de-duplicated, in chain order. */
  certificates: ParsedCertificate[];
  leaf?: ParsedCertificate;
  intermediates: ParsedCertificate[];
  root?: ParsedCertificate;
  /** Certificates that could not be attached to the chain. */
  unrelated: ParsedCertificate[];
  status: ChainStatus;
  /** Cryptographic verification result, kept separate from system trust. */
  cryptographicStatus: 'valid' | 'invalid' | 'unknown';
  /** We have no trust store, so this is always 'unknown'. See spec §31. */
  systemTrust: 'unknown';
  links: ChainLink[];
  issues: ChainIssue[];
  /** Subject of the first missing issuer, when the chain is incomplete. */
  missingIssuer?: string;
}

export interface AnalysisResult {
  decode: DecodeResult;
  chain: CertificateChain;
  /** Fatal problems that prevented any certificate from being parsed. */
  issues: DecodeIssue[];
}
