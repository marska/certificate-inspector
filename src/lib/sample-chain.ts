/**
 * Builds a throwaway demo chain (leaf → intermediate → root) in the browser so
 * the "Load sample" button has something to show without shipping a real
 * certificate or calling out to the network.
 *
 * Loaded dynamically, so none of this is in the initial bundle.
 */
import * as asn1js from 'asn1js';
import {
  AltName,
  AttributeTypeAndValue,
  AuthorityKeyIdentifier,
  BasicConstraints,
  Certificate,
  ExtKeyUsage,
  Extension,
  GeneralName,
  type RelativeDistinguishedNames,
} from 'pkijs';

import { toPem } from '@/lib/certificate/encoding';

const DAY = 86_400_000;

const DN_OIDS: Record<string, string> = {
  CN: '2.5.4.3',
  O: '2.5.4.10',
  L: '2.5.4.7',
  C: '2.5.4.6',
};

export async function buildSampleChain(): Promise<string> {
  const [rootKeys, intermediateKeys, leafKeys] = await Promise.all([
    generateRsaKeys(),
    generateRsaKeys(),
    generateRsaKeys(),
  ]);

  const now = Date.now();
  const rootName = { CN: 'Example Root CA X1', O: 'Example Trust Services', C: 'PL' };
  const intermediateName = {
    CN: 'Example TLS RSA SHA256 2026 CA1',
    O: 'Example Trust Services',
    C: 'PL',
  };
  const leafName = {
    CN: 'api.example.com',
    O: 'Example Company',
    L: 'Warsaw',
    C: 'PL',
  };

  const root = await makeCertificate({
    subject: rootName,
    keys: rootKeys,
    issuerKeys: rootKeys,
    serial: 1,
    notBefore: new Date(now - 1500 * DAY),
    notAfter: new Date(now + 4000 * DAY),
    ca: true,
    keyUsage: [5, 6],
  });

  const intermediate = await makeCertificate({
    subject: intermediateName,
    issuer: rootName,
    keys: intermediateKeys,
    issuerKeys: rootKeys,
    serial: 2,
    notBefore: new Date(now - 800 * DAY),
    notAfter: new Date(now + 1800 * DAY),
    ca: true,
    pathLength: 0,
    keyUsage: [5, 6],
    authorityKeyIdentifier: root.ski,
  });

  const leaf = await makeCertificate({
    subject: leafName,
    issuer: intermediateName,
    keys: leafKeys,
    issuerKeys: intermediateKeys,
    serial: 0x2f5a1c,
    notBefore: new Date(now - 200 * DAY),
    notAfter: new Date(now + 153 * DAY),
    ca: false,
    keyUsage: [0, 2],
    extendedKeyUsage: ['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2'],
    dnsNames: ['api.example.com', 'www.example.com', '*.internal.example.com'],
    ipAddresses: ['10.20.30.40'],
    authorityKeyIdentifier: intermediate.ski,
  });

  return [leaf.pem, intermediate.pem, root.pem].join('\n\n');
}

async function generateRsaKeys(): Promise<CryptoKeyPair> {
  return (await globalThis.crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
}

interface MakeOptions {
  subject: Record<string, string>;
  issuer?: Record<string, string>;
  keys: CryptoKeyPair;
  issuerKeys: CryptoKeyPair;
  serial: number;
  notBefore: Date;
  notAfter: Date;
  ca: boolean;
  pathLength?: number;
  keyUsage: number[];
  extendedKeyUsage?: string[];
  dnsNames?: string[];
  ipAddresses?: string[];
  authorityKeyIdentifier?: Uint8Array;
}

async function makeCertificate(
  options: MakeOptions,
): Promise<{ pem: string; ski: Uint8Array }> {
  const certificate = new Certificate();
  certificate.version = 2;
  certificate.serialNumber = new asn1js.Integer({ value: options.serial });

  fillName(certificate.subject, options.subject);
  fillName(certificate.issuer, options.issuer ?? options.subject);

  certificate.notBefore.value = options.notBefore;
  certificate.notAfter.value = options.notAfter;

  await certificate.subjectPublicKeyInfo.importKey(options.keys.publicKey);

  const spki = new Uint8Array(
    certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView,
  );
  const ski = new Uint8Array(
    await globalThis.crypto.subtle.digest('SHA-1', spki.slice().buffer as ArrayBuffer),
  );

  const basicConstraints = new BasicConstraints({
    cA: options.ca,
    ...(options.pathLength !== undefined
      ? { pathLenConstraint: options.pathLength }
      : {}),
  });

  const extensions: Extension[] = [
    new Extension({
      extnID: '2.5.29.19',
      critical: true,
      extnValue: basicConstraints.toSchema().toBER(false),
      parsedValue: basicConstraints,
    }),
    new Extension({
      extnID: '2.5.29.15',
      critical: true,
      extnValue: keyUsageBits(options.keyUsage).toBER(false),
    }),
    new Extension({
      extnID: '2.5.29.14',
      critical: false,
      extnValue: new asn1js.OctetString({
        valueHex: ski.slice().buffer as ArrayBuffer,
      }).toBER(false),
    }),
  ];

  if (options.extendedKeyUsage?.length) {
    const eku = new ExtKeyUsage({ keyPurposes: options.extendedKeyUsage });
    extensions.push(
      new Extension({
        extnID: '2.5.29.37',
        critical: false,
        extnValue: eku.toSchema().toBER(false),
        parsedValue: eku,
      }),
    );
  }

  if (options.dnsNames?.length || options.ipAddresses?.length) {
    const altNames: GeneralName[] = [
      ...(options.dnsNames ?? []).map(
        (value) => new GeneralName({ type: 2, value }),
      ),
      ...(options.ipAddresses ?? []).map(
        (value) =>
          new GeneralName({
            type: 7,
            value: new asn1js.OctetString({
              valueHex: Uint8Array.from(value.split('.').map(Number)).buffer as ArrayBuffer,
            }),
          }),
      ),
    ];
    const altName = new AltName({ altNames });
    extensions.push(
      new Extension({
        extnID: '2.5.29.17',
        critical: false,
        extnValue: altName.toSchema().toBER(false),
        parsedValue: altName,
      }),
    );
  }

  if (options.authorityKeyIdentifier) {
    const aki = new AuthorityKeyIdentifier({
      keyIdentifier: new asn1js.OctetString({
        valueHex: options.authorityKeyIdentifier.slice().buffer as ArrayBuffer,
      }),
    });
    extensions.push(
      new Extension({
        extnID: '2.5.29.35',
        critical: false,
        extnValue: aki.toSchema().toBER(false),
        parsedValue: aki,
      }),
    );
  }

  certificate.extensions = extensions;
  await certificate.sign(options.issuerKeys.privateKey, 'SHA-256');

  return {
    pem: toPem(new Uint8Array(certificate.toSchema(true).toBER(false))),
    ski,
  };
}

function fillName(target: RelativeDistinguishedNames, values: Record<string, string>) {
  for (const [key, value] of Object.entries(values)) {
    target.typesAndValues.push(
      new AttributeTypeAndValue({
        type: DN_OIDS[key] ?? key,
        value:
          key === 'C'
            ? new asn1js.PrintableString({ value })
            : new asn1js.Utf8String({ value }),
      }),
    );
  }
}

function keyUsageBits(bits: number[]): asn1js.BitString {
  const highest = Math.max(...bits);
  const bytes = new Uint8Array(Math.floor(highest / 8) + 1);
  for (const bit of bits) bytes[bit >> 3] |= 0x80 >> bit % 8;
  return new asn1js.BitString({
    valueHex: bytes.buffer as ArrayBuffer,
    unusedBits: bytes.length * 8 - (highest + 1),
  });
}
