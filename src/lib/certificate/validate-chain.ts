import { Certificate } from 'pkijs';

import { buildChain, isIssuerOf } from './build-chain';
import { buildValidity } from './parse-certificate';
import type {
  CertificateChain,
  ChainIssue,
  ChainLink,
  LinkCheck,
  LinkCheckStatus,
  ParsedCertificate,
} from './types';

export interface ValidateOptions {
  now?: Date;
  /** Set to false to skip WebCrypto signature verification. */
  verifySignatures?: boolean;
}

/**
 * Builds the chain and checks every relation we can check offline:
 * issuer/subject match, AKI/SKI match, and the actual signatures.
 *
 * It deliberately says nothing about system trust — see spec §31. A chain whose
 * signatures all verify is `cryptographicStatus: 'valid'`, never "trusted".
 */
export async function validateChain(
  certificates: ParsedCertificate[],
  options: ValidateOptions = {},
): Promise<CertificateChain> {
  const now = options.now ?? new Date();
  const verifySignatures = options.verifySignatures ?? true;
  const built = buildChain(certificates);
  const issues: ChainIssue[] = [];
  const links: ChainLink[] = [];

  if (built.ordered.length === 0) {
    return {
      certificates: [],
      intermediates: [],
      unrelated: [],
      status: 'unknown',
      cryptographicStatus: 'unknown',
      systemTrust: 'unknown',
      links: [],
      issues,
    };
  }

  /* ---------------- per-certificate diagnostics ---------------- */

  for (const certificate of built.ordered) {
    // Recomputed against this call's clock so the diagnostics never depend on
    // when the certificate happened to be parsed.
    const validity = buildValidity(
      certificate.validity.notBefore,
      certificate.validity.notAfter,
      now,
    );
    const role = roleLabel(certificate);

    if (validity.status === 'expired') {
      issues.push({
        severity: 'error',
        certificateId: certificate.id,
        code: 'CERT_EXPIRED',
        message: `${role} expired ${Math.abs(validity.daysRemaining)} day(s) ago.`,
        detail: `${certificate.label} was valid until ${validity.notAfter.toISOString()}.`,
      });
    } else if (validity.status === 'not-yet-valid') {
      issues.push({
        severity: 'error',
        certificateId: certificate.id,
        code: 'CERT_NOT_YET_VALID',
        message: `${role} is not valid yet.`,
        detail: `${certificate.label} becomes valid on ${validity.notBefore.toISOString()}.`,
      });
    } else if (validity.status === 'expiring-soon') {
      issues.push({
        severity: 'warning',
        certificateId: certificate.id,
        code: 'CERT_EXPIRING_SOON',
        message: `${role} expires in ${validity.daysRemaining} day(s).`,
        detail: `Renew ${certificate.label} before ${validity.notAfter.toISOString()}.`,
      });
    } else {
      issues.push({
        severity: 'success',
        certificateId: certificate.id,
        code: 'CERT_VALID',
        message: `${role} is valid (${validity.daysRemaining} days remaining).`,
      });
    }

    if (certificate.signature.weak) {
      issues.push({
        severity: 'warning',
        certificateId: certificate.id,
        code: 'WEAK_SIGNATURE',
        message: `${role} uses a weak signature algorithm (${certificate.signature.algorithm}).`,
        detail: certificate.signature.weakReason,
      });
    }
  }

  /* ---------------- structural diagnostics ---------------- */

  if (built.leaf?.isSelfSigned) {
    issues.push({
      severity: 'warning',
      certificateId: built.leaf.id,
      code: 'SELF_SIGNED_LEAF',
      message: 'The end-entity certificate is self-signed.',
      detail:
        'Clients will reject it unless the certificate itself has been added to their trust store.',
    });
  }

  if (built.leaf?.isCA) {
    issues.push({
      severity: 'warning',
      certificateId: built.leaf.id,
      code: 'LEAF_IS_CA',
      message: 'The end-entity certificate has CA:TRUE in Basic Constraints.',
      detail:
        'An end-entity certificate should not be a CA. Browsers may reject it, and it ' +
        'is a significant risk if the key is ever compromised.',
    });
  }

  for (const intermediate of built.intermediates) {
    if (!intermediate.basicConstraints.present || !intermediate.isCA) {
      issues.push({
        severity: 'error',
        certificateId: intermediate.id,
        code: 'INVALID_CA_CONSTRAINT',
        message: `${intermediate.label} signs other certificates but is not marked CA:TRUE.`,
        detail:
          'RFC 5280 requires Basic Constraints with CA:TRUE on any certificate that ' +
          'issues other certificates.',
      });
    }
    if (
      intermediate.keyUsage.length > 0 &&
      !intermediate.keyUsage.find((usage) => usage.name === 'Certificate Signing')?.enabled
    ) {
      issues.push({
        severity: 'warning',
        certificateId: intermediate.id,
        code: 'INVALID_CA_CONSTRAINT',
        message: `${intermediate.label} is a CA but its Key Usage omits Certificate Signing.`,
      });
    }
  }

  if (built.root) {
    issues.push({
      severity: 'info',
      certificateId: built.root.id,
      code: 'ROOT_INCLUDED',
      message: 'The root CA is included in the input.',
      detail:
        'A TLS server does not need to send the root certificate — clients must already ' +
        'have it. Sending it only wastes handshake bytes.',
    });
  }

  for (const duplicate of built.duplicates) {
    issues.push({
      severity: 'warning',
      certificateId: duplicate.id,
      code: 'DUPLICATE_CERTIFICATE',
      message: `Duplicate certificate in the input: ${duplicate.label}.`,
      detail: 'The same certificate appears more than once and was shown only once.',
    });
  }

  if (built.wrongOrder) {
    issues.push({
      severity: 'warning',
      certificateId: built.leaf?.id,
      code: 'WRONG_ORDER',
      message: 'The certificates are not in chain order.',
      detail:
        'A TLS bundle should be ordered leaf first, then each issuer in turn. Some ' +
        'clients tolerate a wrong order; others do not.',
    });
  }

  for (const stray of built.unrelated) {
    issues.push({
      severity: 'warning',
      certificateId: stray.id,
      code: 'UNRELATED_CERTIFICATE',
      message: `${stray.label} does not belong to this chain.`,
      detail: `Its issuer (${stray.issuer.oneLine || 'unknown'}) is not part of the chain built from the input.`,
    });
  }

  /* ---------------- link verification ---------------- */

  const pkiCache = new Map<string, Certificate>();
  const pkiOf = (certificate: ParsedCertificate): Certificate => {
    const cached = pkiCache.get(certificate.id);
    if (cached) return cached;
    const parsed = Certificate.fromBER(certificate.der.slice().buffer as ArrayBuffer);
    pkiCache.set(certificate.id, parsed);
    return parsed;
  };

  let verifiedCount = 0;
  let failedCount = 0;

  for (let index = 0; index < built.ordered.length; index++) {
    const subject = built.ordered[index];
    const issuer =
      index + 1 < built.ordered.length
        ? built.ordered[index + 1]
        : subject.isSelfSigned
          ? subject
          : undefined;

    const checks: LinkCheck[] = [];

    if (!issuer) {
      checks.push({
        label: 'Issuer certificate present',
        status: 'fail',
        detail: `No certificate with subject ${subject.issuer.oneLine} was supplied.`,
      });
      links.push({
        subjectId: subject.id,
        subjectLabel: subject.label,
        checks,
      });
      continue;
    }

    const selfLink = issuer.id === subject.id;

    const namesLineUp = selfLink || isIssuerOf(issuer, subject);
    checks.push({
      label: selfLink ? 'Self-signed (issuer = subject)' : 'Issuer matches Subject',
      status: namesLineUp ? 'ok' : 'fail',
      detail: selfLink
        ? undefined
        : namesLineUp
          ? subject.issuer.oneLine
          : `expected ${subject.issuer.oneLine}, found ${issuer.subject.oneLine}`,
    });

    if (subject.authorityKeyIdentifier && issuer.subjectKeyIdentifier) {
      checks.push({
        label: 'Authority Key Identifier matches Subject Key Identifier',
        status:
          subject.authorityKeyIdentifier === issuer.subjectKeyIdentifier ? 'ok' : 'fail',
        detail: `AKI ${subject.authorityKeyIdentifier} / SKI ${issuer.subjectKeyIdentifier}`,
      });
    } else {
      checks.push({
        label: 'Authority Key Identifier matches Subject Key Identifier',
        status: 'skipped',
        detail: 'One of the certificates does not carry a key identifier extension.',
      });
    }

    let signatureStatus: LinkCheckStatus = 'unknown';
    let signatureDetail: string | undefined;

    if (verifySignatures) {
      const result = await verifySignature(pkiOf(subject), pkiOf(issuer));
      signatureStatus = result.status;
      signatureDetail = result.detail;
    } else {
      signatureStatus = 'skipped';
    }

    checks.push({
      label: 'Signature verification',
      status: signatureStatus,
      detail: signatureDetail,
    });

    if (signatureStatus === 'ok') verifiedCount++;
    if (signatureStatus === 'fail') {
      failedCount++;
      issues.push({
        severity: 'error',
        certificateId: subject.id,
        code: 'SIGNATURE_INVALID',
        message: selfLink
          ? `The self-signature of ${subject.label} is invalid.`
          : `${subject.label} was not signed by ${issuer.label}.`,
        detail:
          'The issuer names line up but the signature does not verify against the ' +
          "issuer's public key.",
      });
    }
    if (signatureStatus === 'unknown' && signatureDetail) {
      issues.push({
        severity: 'info',
        certificateId: subject.id,
        code: 'SIGNATURE_UNVERIFIABLE',
        message: `Could not verify the signature of ${subject.label}.`,
        detail: signatureDetail,
      });
    }

    links.push({
      subjectId: subject.id,
      subjectLabel: subject.label,
      issuerId: issuer.id,
      issuerLabel: issuer.label,
      checks,
    });
  }

  /* ---------------- completeness ---------------- */

  let missingIssuer: string | undefined;
  if (built.missingIssuerOf) {
    missingIssuer = built.missingIssuerOf.issuer.oneLine;
    const stoppedAtCa = built.missingIssuerOf.isCA;
    issues.push({
      severity: stoppedAtCa ? 'info' : 'warning',
      certificateId: built.missingIssuerOf.id,
      code: stoppedAtCa ? 'CHAIN_INCOMPLETE' : 'ISSUER_NOT_FOUND',
      message: stoppedAtCa
        ? 'The root CA is not included in the input.'
        : `Missing issuer certificate for ${built.missingIssuerOf.label}.`,
      detail: stoppedAtCa
        ? `The chain stops at ${built.missingIssuerOf.label}, whose issuer is ` +
          `${missingIssuer}. That is normal — TLS servers are not required to send the root.`
        : `No certificate with subject ${missingIssuer} was supplied, so the chain ` +
          'cannot be followed any further. Most clients will reject this bundle.',
    });
  } else if (built.root) {
    issues.push({
      severity: 'success',
      code: 'CHAIN_COMPLETE',
      message: 'The chain terminates at a self-signed root certificate.',
    });
  }

  /* ---------------- overall status ---------------- */

  const hasError = issues.some((issue) => issue.severity === 'error');
  const cryptographicStatus =
    failedCount > 0 ? 'invalid' : verifiedCount > 0 ? 'valid' : 'unknown';

  let status: CertificateChain['status'];
  if (hasError) status = 'invalid';
  else if (built.missingIssuerOf && !built.missingIssuerOf.isCA) status = 'incomplete';
  else if (built.ordered.length === 1 && !built.ordered[0].isSelfSigned) status = 'incomplete';
  else if (cryptographicStatus === 'valid' || built.ordered.length === 1) status = 'valid';
  else status = 'unknown';

  return {
    certificates: built.ordered.concat(built.unrelated),
    leaf: built.leaf,
    intermediates: built.intermediates,
    root: built.root,
    unrelated: built.unrelated,
    status,
    cryptographicStatus,
    systemTrust: 'unknown',
    links,
    issues,
    missingIssuer,
  };
}

async function verifySignature(
  subject: Certificate,
  issuer: Certificate,
): Promise<{ status: LinkCheckStatus; detail?: string }> {
  try {
    const valid = await subject.verify(issuer);
    return {
      status: valid ? 'ok' : 'fail',
      detail: valid ? undefined : 'The signature does not match.',
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      status: 'unknown',
      detail: `This browser's WebCrypto cannot verify this algorithm (${message}).`,
    };
  }
}

function roleLabel(certificate: ParsedCertificate): string {
  switch (certificate.role) {
    case 'leaf':
      return 'End-entity certificate';
    case 'intermediate':
      return 'Intermediate CA';
    case 'root':
      return 'Root CA';
    default:
      return 'Certificate';
  }
}
