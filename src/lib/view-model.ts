import { formatLocal, formatUtc } from '@/lib/certificate/encoding';
import type { ParsedCertificate, ValidityStatus } from '@/lib/certificate/types';
import type { FieldSpec } from '@/components/ui/field';
import type { BadgeTone } from '@/components/ui/primitives';
import { plural } from '@/lib/utils';

export type TimeZoneMode = 'utc' | 'local';

export function formatDate(date: Date, mode: TimeZoneMode): string {
  return mode === 'utc' ? formatUtc(date) : formatLocal(date);
}

export const STATUS_LABEL: Record<ValidityStatus, string> = {
  valid: 'Valid',
  'expiring-soon': 'Expiring soon',
  expired: 'Expired',
  'not-yet-valid': 'Not valid yet',
};

export const STATUS_TONE: Record<ValidityStatus, BadgeTone> = {
  valid: 'success',
  'expiring-soon': 'warning',
  expired: 'danger',
  'not-yet-valid': 'warning',
};

/** "Expires in 153 days" / "Expired 4 days ago" / "Valid in 12 days". */
export function expiryPhrase(certificate: ParsedCertificate): string {
  const { status, daysRemaining, notBefore } = certificate.validity;
  if (status === 'not-yet-valid') {
    const days = Math.ceil((notBefore.getTime() - Date.now()) / 86_400_000);
    return `Valid in ${days} ${plural(days, 'day')}`;
  }
  if (daysRemaining < 0) {
    const days = Math.abs(daysRemaining);
    return `Expired ${days} ${plural(days, 'day')} ago`;
  }
  return `Expires in ${daysRemaining} ${plural(daysRemaining, 'day')}`;
}

export function certificateKind(certificate: ParsedCertificate): string {
  if (certificate.isCA) {
    return certificate.isSelfSigned ? 'Root CA' : 'Intermediate CA';
  }
  return certificate.isSelfSigned ? 'Self-signed end-entity' : 'End-entity (leaf)';
}

export function summaryFields(
  certificate: ParsedCertificate,
  mode: TimeZoneMode,
): FieldSpec[] {
  return [
    {
      label: 'Common Name',
      value: certificate.commonName ?? '',
      terms: ['cn', 'subject'],
      hint: certificate.commonName ? undefined : 'This certificate has no CN attribute.',
    },
    {
      label: 'Subject',
      value: certificate.subject.multiLine,
      multiline: true,
      terms: ['dn', 'distinguished name', certificate.subject.oneLine],
    },
    {
      label: 'Issuer',
      value: certificate.issuer.multiLine,
      multiline: true,
      terms: ['ca', 'issued by', certificate.issuer.oneLine],
    },
    {
      label: 'Serial Number',
      value: certificate.serialNumber,
      terms: ['serial'],
      hint: `Decimal: ${certificate.serialNumberDecimal}`,
    },
    { label: 'Version', value: `${certificate.version} (0x${certificate.version - 1})`, copy: false },
    {
      label: 'Valid From',
      value: formatDate(certificate.validity.notBefore, mode),
      terms: ['not before', 'notbefore'],
    },
    {
      label: 'Valid Until',
      value: formatDate(certificate.validity.notAfter, mode),
      terms: ['not after', 'notafter', 'expiry', 'expiration'],
    },
    {
      label: 'Days Until Expiration',
      value: String(certificate.validity.daysRemaining),
      copy: false,
      terms: ['expires', 'remaining'],
      tone:
        certificate.validity.status === 'expired'
          ? 'danger'
          : certificate.validity.status === 'expiring-soon'
            ? 'warning'
            : 'default',
    },
    {
      label: 'Certificate Authority',
      value: certificate.isCA ? 'Yes' : 'No',
      copy: false,
      terms: ['ca', 'basic constraints'],
    },
    {
      label: 'Self Signed',
      value: certificate.isSelfSigned ? 'Yes' : 'No',
      copy: false,
      terms: ['self-signed'],
    },
  ];
}

export function validityFields(
  certificate: ParsedCertificate,
  mode: TimeZoneMode,
): FieldSpec[] {
  const { validity } = certificate;
  return [
    {
      label: 'Not Before',
      value: formatDate(validity.notBefore, mode),
      terms: ['valid from'],
    },
    {
      label: 'Not After',
      value: formatDate(validity.notAfter, mode),
      terms: ['valid until', 'expiry'],
    },
    {
      label: 'Validity Period',
      value: `${validity.periodDays} ${plural(validity.periodDays, 'day')}`,
      copy: false,
    },
    {
      label: 'Remaining',
      value:
        validity.daysRemaining >= 0
          ? `${validity.daysRemaining} ${plural(validity.daysRemaining, 'day')}`
          : `${Math.abs(validity.daysRemaining)} ${plural(
              validity.daysRemaining,
              'day',
            )} ago`,
      copy: false,
      tone: validity.status === 'valid' ? 'default' : 'warning',
    },
    {
      label: 'Status',
      value: STATUS_LABEL[validity.status],
      copy: false,
      tone:
        validity.status === 'valid'
          ? 'success'
          : validity.status === 'expired'
            ? 'danger'
            : 'warning',
    },
  ];
}

export function publicKeyFields(certificate: ParsedCertificate): FieldSpec[] {
  const { publicKey } = certificate;
  const fields: FieldSpec[] = [
    { label: 'Algorithm', value: publicKey.algorithm, copy: false, terms: ['rsa', 'ecdsa', 'key'] },
  ];

  if (publicKey.curve) {
    fields.push({ label: 'Curve', value: publicKey.curve, terms: ['ecc', 'named curve'] });
  }
  if (publicKey.size) {
    fields.push({ label: 'Key Size', value: `${publicKey.size} bit`, copy: false });
  }
  if (publicKey.exponent !== undefined) {
    fields.push({
      label: 'Public Exponent',
      value: String(publicKey.exponent),
      terms: ['e'],
    });
  }
  if (publicKey.oid) {
    fields.push({ label: 'Algorithm OID', value: publicKey.oid, terms: ['oid'] });
  }
  if (publicKey.curveOid) {
    fields.push({ label: 'Curve OID', value: publicKey.curveOid, terms: ['oid'] });
  }
  if (publicKey.modulusHex) {
    fields.push({
      label: 'Modulus',
      value: publicKey.modulusHex,
      terms: ['n', 'subject public key info'],
    });
  }
  fields.push({
    label: 'Subject Public Key Info',
    value: publicKey.keyHex,
    terms: ['spki', 'raw key'],
  });

  return fields;
}

export function signatureFields(certificate: ParsedCertificate): FieldSpec[] {
  const { signature } = certificate;
  return [
    {
      label: 'Signature Algorithm',
      value: signature.algorithm,
      terms: ['sig'],
      tone: signature.weak ? 'warning' : 'default',
    },
    { label: 'Hash', value: signature.hashAlgorithm ?? '', copy: false, terms: ['digest'] },
    { label: 'Signature Algorithm OID', value: signature.oid ?? '', terms: ['oid'] },
    { label: 'Signature Value', value: signature.valueHex, terms: ['signature bytes'] },
  ];
}

export function basicConstraintsFields(certificate: ParsedCertificate): FieldSpec[] {
  const { basicConstraints } = certificate;
  if (!basicConstraints.present) {
    return [
      {
        label: 'Basic Constraints',
        value: 'Not present',
        copy: false,
        tone: 'muted',
        hint: 'Without this extension the certificate is treated as an end-entity certificate.',
      },
    ];
  }
  return [
    {
      label: 'Certificate Authority',
      value: basicConstraints.ca ? 'Yes' : 'No',
      copy: false,
      terms: ['ca', 'cA'],
    },
    {
      label: 'Path Length',
      value:
        basicConstraints.pathLength !== undefined
          ? String(basicConstraints.pathLength)
          : 'N/A',
      copy: false,
      terms: ['pathlen'],
    },
    {
      label: 'Critical',
      value: basicConstraints.critical ? 'Yes' : 'No',
      copy: false,
    },
  ];
}

export function fingerprintFields(
  certificate: ParsedCertificate,
  withColons: boolean,
): FieldSpec[] {
  const strip = (value: string) => (withColons ? value : value.replace(/:/g, ''));
  return [
    {
      label: 'SHA-256',
      value: strip(certificate.fingerprints.sha256),
      terms: ['fingerprint', 'thumbprint', 'sha256'],
    },
    {
      label: 'SHA-1',
      value: strip(certificate.fingerprints.sha1),
      terms: ['fingerprint', 'thumbprint', 'sha1'],
    },
  ];
}

export function accessFields(certificate: ParsedCertificate): FieldSpec[] {
  const fields: FieldSpec[] = [];
  certificate.ocspUrls.forEach((url, index) =>
    fields.push({
      label: certificate.ocspUrls.length > 1 ? `OCSP URL ${index + 1}` : 'OCSP URL',
      value: url,
      terms: ['ocsp', 'aia', 'authority information access'],
    }),
  );
  certificate.caIssuerUrls.forEach((url, index) =>
    fields.push({
      label:
        certificate.caIssuerUrls.length > 1 ? `CA Issuers URL ${index + 1}` : 'CA Issuers URL',
      value: url,
      terms: ['aia', 'ca issuers', 'authority information access'],
    }),
  );
  certificate.crlDistributionPoints.forEach((url, index) =>
    fields.push({
      label:
        certificate.crlDistributionPoints.length > 1 ? `CRL URL ${index + 1}` : 'CRL URL',
      value: url,
      terms: ['crl', 'revocation', 'distribution point'],
    }),
  );
  if (certificate.subjectKeyIdentifier) {
    fields.push({
      label: 'Subject Key Identifier',
      value: certificate.subjectKeyIdentifier,
      terms: ['ski'],
    });
  }
  if (certificate.authorityKeyIdentifier) {
    fields.push({
      label: 'Authority Key Identifier',
      value: certificate.authorityKeyIdentifier,
      terms: ['aki'],
    });
  }
  return fields;
}
