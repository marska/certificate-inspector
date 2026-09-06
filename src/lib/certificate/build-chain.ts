import { canonicalDn } from './names';
import type { CertificateRole, ParsedCertificate } from './types';

export interface BuiltChain {
  /** Unique certificates, ordered leaf → root as far as the chain resolves. */
  ordered: ParsedCertificate[];
  leaf?: ParsedCertificate;
  intermediates: ParsedCertificate[];
  root?: ParsedCertificate;
  /** Certificates from the input that do not belong to the chain. */
  unrelated: ParsedCertificate[];
  /** Copies removed during de-duplication. */
  duplicates: ParsedCertificate[];
  /** True when the pasted order differs from the resolved chain order. */
  wrongOrder: boolean;
  /** Subject of the issuer the chain stops at, when it is not self-signed. */
  missingIssuerOf?: ParsedCertificate;
}

/** True when `candidate` looks like the issuer of `subject`. */
export function isIssuerOf(
  candidate: ParsedCertificate,
  subject: ParsedCertificate,
): boolean {
  if (candidate.id === subject.id) return false;
  if (canonicalDn(candidate.subject) !== canonicalDn(subject.issuer)) return false;
  // When both key identifiers are present they must agree — this is what keeps
  // cross-signed CAs with identical subjects apart.
  if (subject.authorityKeyIdentifier && candidate.subjectKeyIdentifier) {
    return subject.authorityKeyIdentifier === candidate.subjectKeyIdentifier;
  }
  return true;
}

function isSelfIssued(certificate: ParsedCertificate): boolean {
  return canonicalDn(certificate.subject) === canonicalDn(certificate.issuer);
}

/**
 * Orders a pile of certificates into a chain.
 *
 * No trust store is involved: this only follows issuer → subject links that are
 * present in the input. It sets `role` on the certificates it is given, since
 * a certificate's place in the chain is only knowable here.
 */
export function buildChain(input: ParsedCertificate[]): BuiltChain {
  const unique: ParsedCertificate[] = [];
  const duplicates: ParsedCertificate[] = [];
  const seen = new Set<string>();

  for (const certificate of input) {
    if (seen.has(certificate.id)) duplicates.push(certificate);
    else {
      seen.add(certificate.id);
      unique.push(certificate);
    }
  }

  if (unique.length === 0) {
    return {
      ordered: [],
      intermediates: [],
      unrelated: [],
      duplicates,
      wrongOrder: false,
    };
  }

  const leaf = pickLeaf(unique);
  const ordered: ParsedCertificate[] = [];
  const used = new Set<string>();
  let current: ParsedCertificate | undefined = leaf;
  let missingIssuerOf: ParsedCertificate | undefined;

  while (current && !used.has(current.id)) {
    ordered.push(current);
    used.add(current.id);

    if (current.isSelfSigned) break;

    const issuer: ParsedCertificate | undefined = unique.find(
      (candidate) => !used.has(candidate.id) && isIssuerOf(candidate, current!),
    );
    if (!issuer) {
      missingIssuerOf = current;
      break;
    }
    current = issuer;
  }

  const unrelated = unique.filter((certificate) => !used.has(certificate.id));

  const last = ordered[ordered.length - 1];
  const rootIncluded = ordered.length > 0 && last.isSelfSigned;
  const root = rootIncluded ? last : undefined;

  // A lone self-signed CA is a root, not a leaf.
  const treatFirstAsRoot = ordered.length === 1 && rootIncluded && last.isCA;
  const resolvedLeaf = treatFirstAsRoot ? undefined : ordered[0];

  const intermediates = ordered.filter(
    (certificate) =>
      certificate.id !== resolvedLeaf?.id && certificate.id !== root?.id,
  );

  for (const certificate of ordered) {
    certificate.role = roleOf(certificate, resolvedLeaf, root);
  }
  for (const certificate of unrelated) {
    certificate.role = certificate.isSelfSigned && certificate.isCA ? 'root' : 'unknown';
  }

  const orderedIds = ordered.map((certificate) => certificate.id).join('>');
  const inputIds = unique
    .filter((certificate) => used.has(certificate.id))
    .map((certificate) => certificate.id)
    .join('>');

  return {
    ordered,
    leaf: resolvedLeaf,
    intermediates,
    root,
    unrelated,
    duplicates,
    wrongOrder: ordered.length > 1 && orderedIds !== inputIds,
    missingIssuerOf,
  };
}

function roleOf(
  certificate: ParsedCertificate,
  leaf: ParsedCertificate | undefined,
  root: ParsedCertificate | undefined,
): CertificateRole {
  if (certificate.id === leaf?.id) return 'leaf';
  if (certificate.id === root?.id) return 'root';
  return 'intermediate';
}

/**
 * The leaf is the certificate nothing else was issued by. Ties are broken in
 * favour of a non-CA certificate, then by input order.
 */
function pickLeaf(certificates: ParsedCertificate[]): ParsedCertificate {
  const candidates = certificates.filter(
    (certificate) =>
      !certificates.some(
        (other) => other.id !== certificate.id && isIssuerOf(certificate, other),
      ),
  );

  const pool = candidates.length > 0 ? candidates : certificates;
  return (
    pool.find((certificate) => !certificate.isCA) ??
    pool.find((certificate) => !isSelfIssued(certificate)) ??
    pool[0]
  );
}
