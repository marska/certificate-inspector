import * as asn1js from 'asn1js';
import type {
  AccessDescription,
  DistributionPoint,
  Extension,
  GeneralName,
  GeneralSubtree,
  PolicyInformation,
} from 'pkijs';

import {
  ACCESS_METHOD_OIDS,
  EKU_OIDS,
  EXTENSION_OIDS,
  KEY_USAGE_BITS,
  POLICY_OIDS,
} from './oids';
import { renderGeneralName, asn1Text } from './names';
import { toColonHex, wrap, formatUtc } from './encoding';
import type {
  AccessDescriptionEntry,
  BasicConstraints,
  CertificateExtension,
  ExtendedKeyUsagePurpose,
  KeyUsageFlag,
  SubjectAlternativeName,
} from './types';

export interface ParsedExtensions {
  list: CertificateExtension[];
  subjectAlternativeNames: SubjectAlternativeName[];
  keyUsage: KeyUsageFlag[];
  keyUsageNames: string[];
  keyUsagePresent: boolean;
  extendedKeyUsage: ExtendedKeyUsagePurpose[];
  basicConstraints: BasicConstraints;
  subjectKeyIdentifier?: string;
  authorityKeyIdentifier?: string;
  crlDistributionPoints: string[];
  ocspUrls: string[];
  caIssuerUrls: string[];
  authorityInfoAccess: AccessDescriptionEntry[];
}

const OID = {
  SAN: '2.5.29.17',
  IAN: '2.5.29.18',
  KEY_USAGE: '2.5.29.15',
  EKU: '2.5.29.37',
  BASIC_CONSTRAINTS: '2.5.29.19',
  SKI: '2.5.29.14',
  AKI: '2.5.29.35',
  CRL_DP: '2.5.29.31',
  FRESHEST_CRL: '2.5.29.46',
  AIA: '1.3.6.1.5.5.7.1.1',
  SIA: '1.3.6.1.5.5.7.1.11',
  POLICIES: '2.5.29.32',
  NAME_CONSTRAINTS: '2.5.29.30',
  SCT: '1.3.6.1.4.1.11129.2.4.2',
  POISON: '1.3.6.1.4.1.11129.2.4.3',
  NETSCAPE_COMMENT: '2.16.840.1.113730.1.13',
  PRIVATE_KEY_USAGE_PERIOD: '2.5.29.16',
  OCSP_NO_CHECK: '1.3.6.1.5.5.7.48.1.5',
  TLS_FEATURE: '1.3.6.1.5.5.7.1.24',
} as const;

export function parseExtensions(
  extensions: Extension[] | undefined,
): ParsedExtensions {
  const result: ParsedExtensions = {
    list: [],
    subjectAlternativeNames: [],
    keyUsage: [],
    keyUsageNames: [],
    keyUsagePresent: false,
    extendedKeyUsage: [],
    basicConstraints: { present: false, ca: false, critical: false },
    crlDistributionPoints: [],
    ocspUrls: [],
    caIssuerUrls: [],
    authorityInfoAccess: [],
  };

  for (const extension of extensions ?? []) {
    const oid = extension.extnID;
    const critical = extension.critical === true;
    let value = '';
    let raw = false;

    try {
      switch (oid) {
        case OID.SAN:
        case OID.IAN: {
          const names = generalNames(extension);
          if (oid === OID.SAN) result.subjectAlternativeNames = names;
          value = names.map((n) => `${n.label}: ${n.value}`).join('\n');
          break;
        }

        case OID.KEY_USAGE: {
          const flags = parseKeyUsage(extension);
          result.keyUsage = flags;
          result.keyUsagePresent = true;
          result.keyUsageNames = flags.filter((f) => f.enabled).map((f) => f.name);
          value = result.keyUsageNames.join(', ') || 'None';
          break;
        }

        case OID.EKU: {
          const purposes = parseExtendedKeyUsage(extension);
          result.extendedKeyUsage = purposes;
          value = purposes.map((p) => `${p.name} (${p.oid})`).join('\n');
          break;
        }

        case OID.BASIC_CONSTRAINTS: {
          const parsed = extension.parsedValue as
            | { cA?: boolean; pathLenConstraint?: number | asn1js.Integer }
            | undefined;
          const ca = parsed?.cA === true;
          const pathLength = normalisePathLength(parsed?.pathLenConstraint);
          result.basicConstraints = { present: true, ca, pathLength, critical };
          value =
            `CA: ${ca ? 'TRUE' : 'FALSE'}` +
            (pathLength !== undefined ? `, pathlen: ${pathLength}` : '');
          break;
        }

        case OID.SKI: {
          const octets = innerOctets(extension);
          result.subjectKeyIdentifier = octets ? toColonHex(octets) : undefined;
          value = result.subjectKeyIdentifier ?? '';
          break;
        }

        case OID.AKI: {
          const parsed = extension.parsedValue as
            | {
                keyIdentifier?: asn1js.OctetString;
                authorityCertIssuer?: GeneralName[];
                authorityCertSerialNumber?: asn1js.Integer;
              }
            | undefined;
          const lines: string[] = [];
          if (parsed?.keyIdentifier) {
            result.authorityKeyIdentifier = toColonHex(
              new Uint8Array(parsed.keyIdentifier.valueBlock.valueHexView),
            );
            lines.push(`keyid: ${result.authorityKeyIdentifier}`);
          }
          for (const issuer of parsed?.authorityCertIssuer ?? []) {
            const rendered = renderGeneralName(issuer);
            lines.push(`issuer: ${rendered.label}: ${rendered.value}`);
          }
          if (parsed?.authorityCertSerialNumber) {
            lines.push(
              `serial: ${toColonHex(
                new Uint8Array(parsed.authorityCertSerialNumber.valueBlock.valueHexView),
              )}`,
            );
          }
          value = lines.join('\n');
          break;
        }

        case OID.CRL_DP:
        case OID.FRESHEST_CRL: {
          const parsed = extension.parsedValue as
            | { distributionPoints?: DistributionPoint[] }
            | undefined;
          const urls: string[] = [];
          for (const point of parsed?.distributionPoints ?? []) {
            const names = point.distributionPoint;
            if (Array.isArray(names)) {
              for (const name of names as GeneralName[]) {
                urls.push(renderGeneralName(name).value);
              }
            }
          }
          if (oid === OID.CRL_DP) result.crlDistributionPoints = urls;
          value = urls.join('\n');
          break;
        }

        case OID.AIA:
        case OID.SIA: {
          const parsed = extension.parsedValue as
            | { accessDescriptions?: AccessDescription[] }
            | undefined;
          const entries: AccessDescriptionEntry[] = [];
          for (const description of parsed?.accessDescriptions ?? []) {
            const methodOid = description.accessMethod;
            entries.push({
              methodOid,
              method: ACCESS_METHOD_OIDS[methodOid] ?? methodOid,
              location: renderGeneralName(description.accessLocation).value,
            });
          }
          if (oid === OID.AIA) {
            result.authorityInfoAccess = entries;
            result.ocspUrls = entries
              .filter((e) => e.methodOid === '1.3.6.1.5.5.7.48.1')
              .map((e) => e.location);
            result.caIssuerUrls = entries
              .filter((e) => e.methodOid === '1.3.6.1.5.5.7.48.2')
              .map((e) => e.location);
          }
          value = entries.map((e) => `${e.method}: ${e.location}`).join('\n');
          break;
        }

        case OID.POLICIES: {
          const parsed = extension.parsedValue as
            | { certificatePolicies?: PolicyInformation[] }
            | undefined;
          value = (parsed?.certificatePolicies ?? [])
            .map((policy) => renderPolicy(policy))
            .join('\n');
          break;
        }

        case OID.NAME_CONSTRAINTS: {
          const parsed = extension.parsedValue as
            | { permittedSubtrees?: GeneralSubtree[]; excludedSubtrees?: GeneralSubtree[] }
            | undefined;
          const lines: string[] = [];
          for (const subtree of parsed?.permittedSubtrees ?? []) {
            const rendered = renderGeneralName(subtree.base);
            lines.push(`Permitted: ${rendered.label}: ${rendered.value}`);
          }
          for (const subtree of parsed?.excludedSubtrees ?? []) {
            const rendered = renderGeneralName(subtree.base);
            lines.push(`Excluded: ${rendered.label}: ${rendered.value}`);
          }
          value = lines.join('\n');
          break;
        }

        case OID.SCT: {
          const parsed = extension.parsedValue as
            | { timestamps?: { logID: ArrayBuffer; timestamp: Date }[] }
            | undefined;
          const timestamps = parsed?.timestamps ?? [];
          value = timestamps.length
            ? timestamps
                .map(
                  (entry, index) =>
                    `#${index + 1} log ${toColonHex(
                      new Uint8Array(entry.logID).subarray(0, 8),
                    )}… at ${formatUtc(entry.timestamp)}`,
                )
                .join('\n')
            : 'Present';
          break;
        }

        case OID.POISON: {
          value = 'Pre-certificate poison (this is not a servable certificate)';
          break;
        }

        case OID.OCSP_NO_CHECK: {
          value = 'Present — the OCSP responder certificate need not be checked';
          break;
        }

        case OID.NETSCAPE_COMMENT: {
          value = asn1Text(innerAsn1(extension));
          break;
        }

        case OID.PRIVATE_KEY_USAGE_PERIOD: {
          const parsed = extension.parsedValue as
            | { notBefore?: Date; notAfter?: Date }
            | undefined;
          value = [
            parsed?.notBefore ? `Not Before: ${formatUtc(parsed.notBefore)}` : '',
            parsed?.notAfter ? `Not After: ${formatUtc(parsed.notAfter)}` : '',
          ]
            .filter(Boolean)
            .join('\n');
          break;
        }

        default: {
          const rendered = renderGenericAsn1(extension);
          value = rendered.value;
          raw = rendered.raw;
        }
      }
    } catch {
      const bytes = extensionBytes(extension);
      value = wrap(toColonHex(bytes), 60);
      raw = true;
    }

    if (!value) {
      const bytes = extensionBytes(extension);
      value = bytes.length ? wrap(toColonHex(bytes), 60) : '(empty)';
      raw = true;
    }

    result.list.push({
      oid,
      name: EXTENSION_OIDS[oid] ?? `Unknown extension (${oid})`,
      critical,
      value,
      raw,
    });
  }

  return result;
}

function extensionBytes(extension: Extension): Uint8Array {
  return new Uint8Array(extension.extnValue.valueBlock.valueHexView);
}

function innerAsn1(extension: Extension): asn1js.AsnType | undefined {
  const bytes = extensionBytes(extension);
  const parsed = asn1js.fromBER(bytes.slice().buffer as ArrayBuffer);
  return parsed.offset === -1 ? undefined : parsed.result;
}

function innerOctets(extension: Extension): Uint8Array | undefined {
  const inner = innerAsn1(extension);
  if (inner instanceof asn1js.OctetString) {
    return new Uint8Array(inner.valueBlock.valueHexView);
  }
  return undefined;
}

function generalNames(extension: Extension): SubjectAlternativeName[] {
  const parsed = extension.parsedValue as { altNames?: GeneralName[] } | undefined;
  return (parsed?.altNames ?? []).map(renderGeneralName);
}

/**
 * KeyUsage is not auto-parsed by pkijs, so the BIT STRING is decoded here.
 * Bit order follows RFC 5280 §4.2.1.3.
 */
export function parseKeyUsage(extension: Extension): KeyUsageFlag[] {
  const inner = innerAsn1(extension);
  const bits =
    inner instanceof asn1js.BitString
      ? new Uint8Array(inner.valueBlock.valueHexView)
      : new Uint8Array(0);

  return KEY_USAGE_BITS.map((name, index) => {
    const byte = bits[index >> 3] ?? 0;
    const enabled = ((byte >> (7 - (index % 8))) & 1) === 1;
    return { name, enabled };
  });
}

function parseExtendedKeyUsage(extension: Extension): ExtendedKeyUsagePurpose[] {
  const parsed = extension.parsedValue as { keyPurposes?: string[] } | undefined;
  return (parsed?.keyPurposes ?? []).map((oid) => ({
    oid,
    name: EKU_OIDS[oid] ?? oid,
    known: oid in EKU_OIDS,
  }));
}

function normalisePathLength(
  value: number | asn1js.Integer | undefined,
): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value === 'number') return value;
  const parsed = Number(value.valueBlock.toString());
  return Number.isFinite(parsed) ? parsed : undefined;
}

function renderPolicy(policy: PolicyInformation): string {
  const oid = policy.policyIdentifier;
  const name = POLICY_OIDS[oid];
  const lines = [name ? `${name} (${oid})` : oid];
  for (const qualifier of policy.policyQualifiers ?? []) {
    const text = asn1Text(qualifier.qualifier);
    if (text) lines.push(`  ${qualifier.policyQualifierId}: ${text}`);
  }
  return lines.join('\n');
}

/** Fallback renderer: readable ASN.1 for simple shapes, hex otherwise. */
function renderGenericAsn1(extension: Extension): { value: string; raw: boolean } {
  const inner = innerAsn1(extension);
  if (!inner) {
    return { value: wrap(toColonHex(extensionBytes(extension)), 60), raw: true };
  }

  if (
    inner instanceof asn1js.Boolean ||
    inner instanceof asn1js.Integer ||
    inner instanceof asn1js.ObjectIdentifier ||
    inner instanceof asn1js.Utf8String ||
    inner instanceof asn1js.PrintableString ||
    inner instanceof asn1js.IA5String ||
    inner instanceof asn1js.BmpString
  ) {
    return { value: asn1Text(inner), raw: false };
  }

  if (inner instanceof asn1js.BitString) {
    return {
      value: toColonHex(new Uint8Array(inner.valueBlock.valueHexView)),
      raw: true,
    };
  }

  if (inner instanceof asn1js.Sequence || inner instanceof asn1js.Set) {
    const parts = (inner.valueBlock.value as asn1js.AsnType[])
      .map((child) => asn1Text(child))
      .filter(Boolean);
    if (parts.length) return { value: parts.join('\n'), raw: false };
  }

  return { value: wrap(toColonHex(extensionBytes(extension)), 60), raw: true };
}
