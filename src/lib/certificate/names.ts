import * as asn1js from 'asn1js';
import type { GeneralName, RelativeDistinguishedNames } from 'pkijs';

import { DN_OIDS } from './oids';
import type {
  DistinguishedName,
  DistinguishedNameAttribute,
  SanType,
  SubjectAlternativeName,
} from './types';
import { bytesToIpAddress, toColonHex } from './encoding';

/** Best-effort text extraction from any asn1js value used inside a name. */
export function asn1Text(value: unknown): string {
  if (value == null) return '';
  if (typeof value === 'string') return value;

  const block = value as { valueBlock?: { value?: unknown; valueHexView?: Uint8Array } };
  const inner = block.valueBlock?.value;
  if (typeof inner === 'string') return inner;
  if (typeof inner === 'number' || typeof inner === 'bigint') return String(inner);

  if (value instanceof asn1js.ObjectIdentifier) return value.valueBlock.toString();
  if (value instanceof asn1js.OctetString) {
    return toColonHex(new Uint8Array(value.valueBlock.valueHexView));
  }

  const hex = block.valueBlock?.valueHexView;
  if (hex && hex.length > 0) return toColonHex(new Uint8Array(hex));

  try {
    return String((value as { toString(): string }).toString());
  } catch {
    return '';
  }
}

/** RFC 4514-ish escaping so values containing separators stay unambiguous. */
function escapeDnValue(value: string): string {
  return value
    .replace(/([,+"\\<>;])/g, '\\$1')
    .replace(/^([ #])/, '\\$1')
    .replace(/ $/, '\\ ');
}

export function parseDistinguishedName(
  rdn: RelativeDistinguishedNames | undefined,
): DistinguishedName {
  const attributes: DistinguishedNameAttribute[] = [];

  for (const attribute of rdn?.typesAndValues ?? []) {
    const oid = attribute.type;
    const known = DN_OIDS[oid];
    attributes.push({
      oid,
      shortName: known?.short ?? oid,
      longName: known?.long ?? `Unknown (${oid})`,
      value: asn1Text(attribute.value),
    });
  }

  const oneLine = attributes
    .map((a) => `${a.shortName}=${escapeDnValue(a.value)}`)
    .join(', ');
  const multiLine = attributes
    .map((a) => `${a.shortName}=${a.value}`)
    .join('\n');

  return { attributes, oneLine, multiLine };
}

/** First value of an attribute, e.g. `dnValue(subject, 'CN')`. */
export function dnValue(
  name: DistinguishedName,
  shortName: string,
): string | undefined {
  return name.attributes.find((a) => a.shortName === shortName)?.value;
}

/** Canonical form used to compare an issuer DN against a subject DN. */
export function canonicalDn(name: DistinguishedName): string {
  return name.attributes
    .map((a) => `${a.oid}=${a.value.trim().toLowerCase().replace(/\s+/g, ' ')}`)
    .join(',');
}

const SAN_TYPES: Record<number, { type: SanType; label: string }> = {
  0: { type: 'other', label: 'Other Name' },
  1: { type: 'email', label: 'Email' },
  2: { type: 'dns', label: 'DNS' },
  3: { type: 'other', label: 'X.400 Address' },
  4: { type: 'dirname', label: 'Directory Name' },
  5: { type: 'other', label: 'EDI Party Name' },
  6: { type: 'uri', label: 'URI' },
  7: { type: 'ip', label: 'IP' },
  8: { type: 'other', label: 'Registered ID' },
};

export function renderGeneralName(name: GeneralName): SubjectAlternativeName {
  const meta = SAN_TYPES[name.type] ?? { type: 'other' as SanType, label: 'Other' };

  let value: string;
  switch (name.type) {
    case 7: {
      const octets = name.value as asn1js.OctetString;
      value = bytesToIpAddress(new Uint8Array(octets.valueBlock.valueHexView));
      break;
    }
    case 4: {
      value = parseDistinguishedName(name.value as RelativeDistinguishedNames).oneLine;
      break;
    }
    case 0: {
      value = renderOtherName(name.value);
      break;
    }
    default:
      value = asn1Text(name.value);
  }

  return { type: meta.type, label: meta.label, value };
}

function renderOtherName(value: unknown): string {
  // OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY }
  const sequence = value as { valueBlock?: { value?: unknown[] } };
  const parts = sequence?.valueBlock?.value;
  if (!Array.isArray(parts) || parts.length === 0) return asn1Text(value);

  const oid = parts[0] instanceof asn1js.ObjectIdentifier
    ? parts[0].valueBlock.toString()
    : asn1Text(parts[0]);

  const payload = parts[1] as { valueBlock?: { value?: unknown[] } } | undefined;
  const innerValue = payload?.valueBlock?.value?.[0] ?? payload;
  const text = asn1Text(innerValue);
  return text ? `${oid}: ${text}` : oid;
}
