import { DN_OIDS, EXTENSION_OIDS, PUBLIC_KEY_OIDS, SIGNATURE_OIDS } from './oids';
import { readDerHeader } from './detect-format';
import { toColonHex } from './encoding';
import type { Asn1Node } from './types';

const UNIVERSAL_TAGS: Record<number, string> = {
  1: 'BOOLEAN',
  2: 'INTEGER',
  3: 'BIT STRING',
  4: 'OCTET STRING',
  5: 'NULL',
  6: 'OBJECT IDENTIFIER',
  10: 'ENUMERATED',
  12: 'UTF8String',
  16: 'SEQUENCE',
  17: 'SET',
  18: 'NumericString',
  19: 'PrintableString',
  20: 'T61String',
  22: 'IA5String',
  23: 'UTCTime',
  24: 'GeneralizedTime',
  26: 'VisibleString',
  27: 'GeneralString',
  28: 'UniversalString',
  30: 'BMPString',
};

const STRING_TAGS = new Set([12, 18, 19, 20, 22, 26, 27, 28]);
const MAX_HEX_BYTES = 48;

/**
 * Walks a DER buffer into a display tree.
 *
 * Written against the bytes rather than an ASN.1 library object so that every
 * node can report its real offset and length, which is what makes this view
 * useful when comparing against `openssl asn1parse`.
 */
export function parseAsn1(bytes: Uint8Array, offset = 0): Asn1Node | undefined {
  const header = readDerHeader(bytes, offset);
  if (!header.ok) return undefined;

  const tagClass = (header.tag & 0xc0) >> 6;
  const constructed = (header.tag & 0x20) !== 0;
  const tagNumber = header.tag & 0x1f;
  const contentStart = offset + header.headerLength;
  const contentEnd = Math.min(contentStart + header.contentLength, bytes.length);
  const content = bytes.subarray(contentStart, contentEnd);

  const node: Asn1Node = {
    name: '',
    type: typeName(tagClass, tagNumber, constructed),
    offset,
    length: header.totalLength,
  };
  node.name = node.type;

  if (constructed) {
    node.children = [];
    let cursor = contentStart;
    let guard = 0;
    while (cursor < contentEnd && guard++ < 4096) {
      const child = parseAsn1(bytes, cursor);
      if (!child || child.length <= 0) break;
      node.children.push(child);
      cursor += child.length;
    }
    // A wrapper whose content is itself DER (OCTET STRING holding an extension)
    // is handled by the annotator, not here.
    return node;
  }

  node.value = formatPrimitive(tagClass, tagNumber, content);
  return node;
}

function typeName(tagClass: number, tagNumber: number, constructed: boolean): string {
  if (tagClass === 0) {
    return UNIVERSAL_TAGS[tagNumber] ?? `UNIVERSAL ${tagNumber}`;
  }
  const prefix = tagClass === 2 ? '' : tagClass === 1 ? 'APPLICATION ' : 'PRIVATE ';
  return `[${prefix}${tagNumber}]${constructed ? '' : ' (primitive)'}`;
}

function formatPrimitive(
  tagClass: number,
  tagNumber: number,
  content: Uint8Array,
): string {
  if (tagClass !== 0) return hex(content);

  switch (tagNumber) {
    case 1:
      return content[0] ? 'TRUE' : 'FALSE';
    case 2:
    case 10:
      return formatInteger(content);
    case 3:
      return content.length > 1
        ? `${content[0]} unused bit(s), ${hex(content.subarray(1))}`
        : '(empty)';
    case 5:
      return 'NULL';
    case 6:
      return decodeOid(content);
    case 23:
    case 24:
      return new TextDecoder().decode(content);
    default:
      if (STRING_TAGS.has(tagNumber)) return new TextDecoder().decode(content);
      if (tagNumber === 30) return decodeBmp(content);
      return hex(content);
  }
}

function formatInteger(content: Uint8Array): string {
  if (content.length === 0) return '0';
  if (content.length <= 6) {
    let value = 0;
    const negative = (content[0] & 0x80) !== 0;
    for (const byte of content) value = value * 256 + byte;
    if (negative) value -= 256 ** content.length;
    return String(value);
  }
  return `0x${toColonHex(content).replace(/:/g, '')}`;
}

export function decodeOid(content: Uint8Array): string {
  if (content.length === 0) return '';
  const parts: number[] = [];
  const first = content[0];
  parts.push(Math.floor(first / 40), first % 40);
  let value = 0;
  for (let i = 1; i < content.length; i++) {
    value = value * 128 + (content[i] & 0x7f);
    if ((content[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

function decodeBmp(content: Uint8Array): string {
  let out = '';
  for (let i = 0; i + 1 < content.length; i += 2) {
    out += String.fromCharCode((content[i] << 8) | content[i + 1]);
  }
  return out;
}

function hex(content: Uint8Array): string {
  if (content.length === 0) return '(empty)';
  if (content.length <= MAX_HEX_BYTES) return toColonHex(content);
  return `${toColonHex(content.subarray(0, MAX_HEX_BYTES))}… (${content.length} bytes)`;
}

/* ------------------------------------------------------------------ */
/* X.509 naming overlay                                                */
/* ------------------------------------------------------------------ */

/** Parses a certificate and labels the nodes with their X.509 field names. */
export function certificateAsn1Tree(der: Uint8Array): Asn1Node | undefined {
  const root = parseAsn1(der);
  if (!root) return undefined;
  annotateCertificate(root, der);
  return root;
}

function annotateCertificate(root: Asn1Node, der: Uint8Array): void {
  root.name = 'Certificate';
  const [tbs, signatureAlgorithm, signatureValue] = root.children ?? [];

  if (tbs) {
    tbs.name = 'tbsCertificate';
    annotateTbs(tbs, der);
  }
  if (signatureAlgorithm) {
    signatureAlgorithm.name = 'signatureAlgorithm';
    annotateAlgorithm(signatureAlgorithm);
  }
  if (signatureValue) signatureValue.name = 'signatureValue';
}

function annotateTbs(tbs: Asn1Node, der: Uint8Array): void {
  const children = tbs.children ?? [];
  let index = 0;

  if (children[0]?.type === '[0]') {
    children[0].name = 'version';
    const inner = children[0].children?.[0];
    if (inner) inner.name = `version (v${Number(inner.value ?? 0) + 1})`;
    index = 1;
  }

  const assign = (name: string, annotate?: (node: Asn1Node) => void) => {
    const node = children[index++];
    if (!node) return;
    node.name = name;
    annotate?.(node);
  };

  assign('serialNumber');
  assign('signature', annotateAlgorithm);
  assign('issuer', annotateName);
  assign('validity', (node) => {
    const [notBefore, notAfter] = node.children ?? [];
    if (notBefore) notBefore.name = 'notBefore';
    if (notAfter) notAfter.name = 'notAfter';
  });
  assign('subject', annotateName);
  assign('subjectPublicKeyInfo', (node) => {
    const [algorithm, key] = node.children ?? [];
    if (algorithm) {
      algorithm.name = 'algorithm';
      annotateAlgorithm(algorithm);
    }
    if (key) key.name = 'subjectPublicKey';
  });

  for (; index < children.length; index++) {
    const node = children[index];
    if (node.type === '[1]') node.name = 'issuerUniqueID';
    else if (node.type === '[2]') node.name = 'subjectUniqueID';
    else if (node.type === '[3]') {
      node.name = 'extensions';
      const list = node.children?.[0];
      if (list) {
        list.name = 'Extensions';
        for (const extension of list.children ?? []) {
          annotateExtension(extension, der);
        }
      }
    }
  }
}

function annotateAlgorithm(node: Asn1Node): void {
  const [algorithm, parameters] = node.children ?? [];
  if (algorithm) {
    // The OID itself is already shown as the node value; the label adds the
    // human-readable name where we know one.
    const oid = algorithm.value ?? '';
    const known = SIGNATURE_OIDS[oid]?.name ?? PUBLIC_KEY_OIDS[oid];
    algorithm.name = known ? `algorithm (${known})` : 'algorithm';
  }
  if (parameters) parameters.name = 'parameters';
}

function annotateName(node: Asn1Node): void {
  node.name = `${node.name} (RDNSequence)`;
  for (const rdn of node.children ?? []) {
    rdn.name = 'RelativeDistinguishedName';
    for (const attribute of rdn.children ?? []) {
      attribute.name = 'AttributeTypeAndValue';
      const [type, value] = attribute.children ?? [];
      if (type) {
        const known = DN_OIDS[type.value ?? ''];
        type.name = known ? `type (${known.long})` : 'type';
      }
      if (value) value.name = 'value';
    }
  }
}

function annotateExtension(extension: Asn1Node, der: Uint8Array): void {
  const children = extension.children ?? [];
  const oid = children[0]?.value ?? '';
  extension.name = `Extension: ${EXTENSION_OIDS[oid] ?? oid}`;
  if (children[0]) children[0].name = 'extnID';

  const critical = children.find((child) => child.type === 'BOOLEAN');
  if (critical) critical.name = 'critical';

  const value = children.find((child) => child.type === 'OCTET STRING');
  if (!value) return;
  value.name = 'extnValue';

  // The extension payload is itself DER — decode it in place so the tree is useful.
  const header = readDerHeader(der, value.offset);
  if (!header.ok) return;
  const inner = parseAsn1(der, value.offset + header.headerLength);
  if (inner) {
    inner.name = `${inner.type} (decoded)`;
    value.children = [inner];
  }
}
