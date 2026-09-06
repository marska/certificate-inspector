import {
  EKU,
  KEY_USAGE,
  SAN_TYPE,
  createCertificate,
  generateKeys,
  type GeneratedCertificate,
  type KeyPairInfo,
} from './factory';

/** Fixed clock so every validity assertion is deterministic. */
export const NOW = new Date('2026-08-12T12:00:00Z');

const day = 86_400_000;
const at = (days: number) => new Date(NOW.getTime() + days * day);

export interface Fixtures {
  root: GeneratedCertificate;
  intermediate: GeneratedCertificate;
  leaf: GeneratedCertificate;
  /** Leaf signed by an intermediate that is missing CA:TRUE. */
  badCaIntermediate: GeneratedCertificate;
  leafUnderBadCa: GeneratedCertificate;
  eccLeaf: GeneratedCertificate;
  /** Self-signed EC CA — exercises ECDSA signature parsing. */
  eccRoot: GeneratedCertificate;
  expiredLeaf: GeneratedCertificate;
  futureLeaf: GeneratedCertificate;
  expiringSoonLeaf: GeneratedCertificate;
  noSanLeaf: GeneratedCertificate;
  selfSignedLeaf: GeneratedCertificate;
  sha1Leaf: GeneratedCertificate;
  forgedLeaf: GeneratedCertificate;
  /** A self-signed CA unrelated to the main chain. */
  otherRoot: GeneratedCertificate;
}

let cache: Promise<Fixtures> | undefined;

/** Built once per test process — RSA key generation is the slow part. */
export function fixtures(): Promise<Fixtures> {
  cache ??= build();
  return cache;
}

async function build(): Promise<Fixtures> {
  const [rootKeys, intermediateKeys, leafKeys, spareKeys]: KeyPairInfo[] =
    await Promise.all([
      generateKeys('RSA'),
      generateKeys('RSA'),
      generateKeys('RSA'),
      generateKeys('RSA'),
    ]);

  const rootName = { CN: 'Example Root CA', O: 'Example Trust Services', C: 'PL' };
  const intermediateName = { CN: 'Example TLS Intermediate CA', O: 'Example Trust Services', C: 'PL' };
  const leafName = { CN: 'api.example.com', O: 'Example Company', L: 'Warsaw', C: 'PL' };

  const root = await createCertificate({
    subject: rootName,
    keys: rootKeys,
    serialNumber: 1,
    notBefore: at(-2000),
    notAfter: at(5000),
    ca: true,
    keyUsage: [KEY_USAGE.keyCertSign, KEY_USAGE.cRLSign],
  });

  const intermediate = await createCertificate({
    subject: intermediateName,
    issuer: rootName,
    keys: intermediateKeys,
    issuerKeys: rootKeys,
    serialNumber: 2,
    notBefore: at(-1000),
    notAfter: at(2000),
    ca: true,
    pathLength: 0,
    keyUsage: [KEY_USAGE.digitalSignature, KEY_USAGE.keyCertSign, KEY_USAGE.cRLSign],
    authorityKeyIdentifier: root.subjectKeyIdentifier,
  });

  const leafDefaults = {
    subject: leafName,
    issuer: intermediateName,
    issuerKeys: intermediateKeys,
    keyUsage: [KEY_USAGE.digitalSignature, KEY_USAGE.keyEncipherment],
    extendedKeyUsage: [EKU.serverAuth, EKU.clientAuth],
    ca: false,
    san: [
      { type: SAN_TYPE.dns, value: 'api.example.com' },
      { type: SAN_TYPE.dns, value: 'www.example.com' },
      { type: SAN_TYPE.dns, value: '*.internal.example.com' },
      { type: SAN_TYPE.ip, value: new Uint8Array([10, 20, 30, 40]) },
    ],
    authorityKeyIdentifier: intermediate.subjectKeyIdentifier,
  };

  const leaf = await createCertificate({
    ...leafDefaults,
    keys: leafKeys,
    serialNumber: 100,
    notBefore: at(-200),
    notAfter: at(165),
  });

  const expiredLeaf = await createCertificate({
    ...leafDefaults,
    keys: leafKeys,
    serialNumber: 101,
    notBefore: at(-400),
    notAfter: at(-35),
  });

  const futureLeaf = await createCertificate({
    ...leafDefaults,
    keys: leafKeys,
    serialNumber: 102,
    notBefore: at(30),
    notAfter: at(395),
  });

  const expiringSoonLeaf = await createCertificate({
    ...leafDefaults,
    keys: leafKeys,
    serialNumber: 103,
    notBefore: at(-347),
    notAfter: at(18),
  });

  const noSanLeaf = await createCertificate({
    subject: { CN: 'legacy.example.com', O: 'Example Company', C: 'PL' },
    issuer: intermediateName,
    issuerKeys: intermediateKeys,
    keys: spareKeys,
    serialNumber: 104,
    notBefore: at(-100),
    notAfter: at(265),
    ca: false,
    authorityKeyIdentifier: intermediate.subjectKeyIdentifier,
  });

  const eccLeaf = await createCertificate({
    ...leafDefaults,
    subject: { CN: 'ecc.example.com', O: 'Example Company', C: 'PL' },
    algorithm: 'EC-P256',
    keys: undefined,
    serialNumber: 105,
    notBefore: at(-50),
    notAfter: at(315),
  });

  const selfSignedLeaf = await createCertificate({
    subject: { CN: 'self.example.com', O: 'Homelab', C: 'PL' },
    keys: spareKeys,
    serialNumber: 106,
    notBefore: at(-10),
    notAfter: at(355),
    ca: false,
    keyUsage: [KEY_USAGE.digitalSignature, KEY_USAGE.keyEncipherment],
    san: [{ type: SAN_TYPE.dns, value: 'self.example.com' }],
  });

  // Self-signed with a SHA-1 key so the signature really is sha1WithRSAEncryption.
  const sha1Leaf = await createCertificate({
    subject: { CN: 'old.example.com', O: 'Example Company', C: 'PL' },
    algorithm: 'RSA-SHA1',
    serialNumber: 107,
    notBefore: at(-100),
    notAfter: at(265),
    ca: false,
    keyUsage: [KEY_USAGE.digitalSignature, KEY_USAGE.keyEncipherment],
    san: [{ type: SAN_TYPE.dns, value: 'old.example.com' }],
    hash: 'SHA-1',
  });

  // Self-signed EC CA, used to exercise ECDSA signature parsing.
  const eccRoot = await createCertificate({
    subject: { CN: 'Example ECC Root CA', O: 'Example Trust Services', C: 'PL' },
    algorithm: 'EC-P384',
    serialNumber: 400,
    notBefore: at(-500),
    notAfter: at(2500),
    ca: true,
    keyUsage: [KEY_USAGE.keyCertSign, KEY_USAGE.cRLSign],
    hash: 'SHA-384',
  });

  const forgedLeaf = await createCertificate({
    ...leafDefaults,
    subject: { CN: 'forged.example.com', O: 'Example Company', C: 'PL' },
    keys: leafKeys,
    serialNumber: 108,
    notBefore: at(-100),
    notAfter: at(265),
    breakSignature: true,
  });

  const badCaName = { CN: 'Not A Real CA', O: 'Example Company', C: 'PL' };
  const badCaIntermediate = await createCertificate({
    subject: badCaName,
    issuer: rootName,
    keys: spareKeys,
    issuerKeys: rootKeys,
    serialNumber: 200,
    notBefore: at(-100),
    notAfter: at(900),
    ca: false,
    authorityKeyIdentifier: root.subjectKeyIdentifier,
  });

  const leafUnderBadCa = await createCertificate({
    subject: { CN: 'under-bad-ca.example.com', C: 'PL' },
    issuer: badCaName,
    keys: leafKeys,
    issuerKeys: spareKeys,
    serialNumber: 201,
    notBefore: at(-50),
    notAfter: at(315),
    ca: false,
    authorityKeyIdentifier: badCaIntermediate.subjectKeyIdentifier,
  });

  const otherRoot = await createCertificate({
    subject: { CN: 'Unrelated Root CA', O: 'Somewhere Else', C: 'DE' },
    serialNumber: 300,
    notBefore: at(-1500),
    notAfter: at(3000),
    ca: true,
    keyUsage: [KEY_USAGE.keyCertSign, KEY_USAGE.cRLSign],
  });

  return {
    root,
    intermediate,
    leaf,
    badCaIntermediate,
    leafUnderBadCa,
    eccLeaf,
    eccRoot,
    expiredLeaf,
    futureLeaf,
    expiringSoonLeaf,
    noSanLeaf,
    selfSignedLeaf,
    sha1Leaf,
    forgedLeaf,
    otherRoot,
  };
}

/** Joins PEM blocks the way a bundle file does. */
export function bundle(...certificates: GeneratedCertificate[]): string {
  return certificates.map((certificate) => certificate.pem).join('\n\n');
}
