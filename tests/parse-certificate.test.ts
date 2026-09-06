import { describe, expect, it } from 'vitest';

import { parseCertificate } from '../src/lib/certificate/parse-certificate';
import { buildValidity } from '../src/lib/certificate';
import { NOW, fixtures } from './fixtures';

describe('parseCertificate', () => {
  it('reads subject, issuer and serial from an RSA leaf', async () => {
    const { leaf } = await fixtures();
    const parsed = await parseCertificate(leaf.der, { now: NOW });

    expect(parsed.commonName).toBe('api.example.com');
    expect(parsed.subject.oneLine).toBe(
      'CN=api.example.com, O=Example Company, L=Warsaw, C=PL',
    );
    expect(parsed.subject.attributes[0]).toMatchObject({
      shortName: 'CN',
      longName: 'Common Name',
      oid: '2.5.4.3',
    });
    expect(parsed.issuer.oneLine).toContain('CN=Example TLS Intermediate CA');
    expect(parsed.version).toBe(3);
    expect(parsed.serialNumber).toBe('64');
    expect(parsed.serialNumberDecimal).toBe('100');
    expect(parsed.label).toBe('api.example.com');
  });

  it('computes validity, remaining days and elapsed fraction', async () => {
    const { leaf } = await fixtures();
    const parsed = await parseCertificate(leaf.der, { now: NOW });

    expect(parsed.validity.status).toBe('valid');
    expect(parsed.validity.daysRemaining).toBe(165);
    expect(parsed.validity.periodDays).toBe(365);
    expect(parsed.validity.elapsedFraction).toBeCloseTo(200 / 365, 3);
  });

  it('flags an expired certificate', async () => {
    const { expiredLeaf } = await fixtures();
    const parsed = await parseCertificate(expiredLeaf.der, { now: NOW });

    expect(parsed.validity.status).toBe('expired');
    expect(parsed.validity.daysRemaining).toBe(-35);
  });

  it('flags a certificate that is not valid yet', async () => {
    const { futureLeaf } = await fixtures();
    const parsed = await parseCertificate(futureLeaf.der, { now: NOW });

    expect(parsed.validity.status).toBe('not-yet-valid');
    expect(parsed.validity.elapsedFraction).toBe(0);
  });

  it('flags a certificate expiring inside the warning window', async () => {
    const { expiringSoonLeaf } = await fixtures();
    const parsed = await parseCertificate(expiringSoonLeaf.der, { now: NOW });

    expect(parsed.validity.status).toBe('expiring-soon');
    expect(parsed.validity.daysRemaining).toBe(18);
  });

  it('extracts every subject alternative name with its type', async () => {
    const { leaf } = await fixtures();
    const parsed = await parseCertificate(leaf.der, { now: NOW });

    expect(parsed.subjectAlternativeNames).toEqual([
      { type: 'dns', label: 'DNS', value: 'api.example.com' },
      { type: 'dns', label: 'DNS', value: 'www.example.com' },
      { type: 'dns', label: 'DNS', value: '*.internal.example.com' },
      { type: 'ip', label: 'IP', value: '10.20.30.40' },
    ]);
  });

  it('handles a certificate without a SAN extension', async () => {
    const { noSanLeaf } = await fixtures();
    const parsed = await parseCertificate(noSanLeaf.der, { now: NOW });

    expect(parsed.subjectAlternativeNames).toEqual([]);
    expect(parsed.commonName).toBe('legacy.example.com');
  });

  it('describes an RSA public key', async () => {
    const { leaf } = await fixtures();
    const parsed = await parseCertificate(leaf.der, { now: NOW });

    expect(parsed.publicKey.algorithm).toBe('RSA');
    expect(parsed.publicKey.size).toBe(2048);
    expect(parsed.publicKey.exponent).toBe(65537);
    expect(parsed.publicKey.oid).toBe('1.2.840.113549.1.1.1');
    expect(parsed.publicKey.modulusHex).toMatch(/^[0-9A-F]{2}(:[0-9A-F]{2})+$/);
  });

  it('describes an ECDSA public key with its curve', async () => {
    const { eccLeaf } = await fixtures();
    const parsed = await parseCertificate(eccLeaf.der, { now: NOW });

    expect(parsed.publicKey.algorithm).toBe('ECDSA');
    expect(parsed.publicKey.curve).toBe('prime256v1 / secp256r1');
    expect(parsed.publicKey.curveOid).toBe('1.2.840.10045.3.1.7');
    expect(parsed.publicKey.size).toBe(256);
  });

  it('reads an ECDSA signature and a P-384 key', async () => {
    const { eccRoot } = await fixtures();
    const parsed = await parseCertificate(eccRoot.der, { now: NOW });

    expect(parsed.signature.algorithm).toBe('ecdsaWithSHA384');
    expect(parsed.signature.hashAlgorithm).toBe('SHA-384');
    expect(parsed.publicKey.curve).toBe('secp384r1');
    expect(parsed.publicKey.size).toBe(384);
  });

  it('reads the signature algorithm and hash', async () => {
    const { leaf } = await fixtures();
    const parsed = await parseCertificate(leaf.der, { now: NOW });

    expect(parsed.signature.algorithm).toBe('sha256WithRSAEncryption');
    expect(parsed.signature.oid).toBe('1.2.840.113549.1.1.11');
    expect(parsed.signature.hashAlgorithm).toBe('SHA-256');
    expect(parsed.signature.weak).toBe(false);
  });

  it('marks SHA-1 signatures as weak', async () => {
    const { sha1Leaf } = await fixtures();
    const parsed = await parseCertificate(sha1Leaf.der, { now: NOW });

    expect(parsed.signature.hashAlgorithm).toBe('SHA-1');
    expect(parsed.signature.weak).toBe(true);
    expect(parsed.signature.weakReason).toContain('deprecated');
  });

  it('decodes key usage into named flags', async () => {
    const { leaf } = await fixtures();
    const parsed = await parseCertificate(leaf.der, { now: NOW });

    expect(parsed.keyUsageNames).toEqual(['Digital Signature', 'Key Encipherment']);
    expect(parsed.keyUsage.find((f) => f.name === 'Certificate Signing')?.enabled).toBe(
      false,
    );
    expect(parsed.keyUsage).toHaveLength(9);
  });

  it('decodes extended key usage with names and OIDs', async () => {
    const { leaf } = await fixtures();
    const parsed = await parseCertificate(leaf.der, { now: NOW });

    expect(parsed.extendedKeyUsage).toEqual([
      { name: 'TLS Web Server Authentication', oid: '1.3.6.1.5.5.7.3.1', known: true },
      { name: 'TLS Web Client Authentication', oid: '1.3.6.1.5.5.7.3.2', known: true },
    ]);
  });

  it('reads basic constraints for a leaf, an intermediate and a root', async () => {
    const { leaf, intermediate, root } = await fixtures();

    const parsedLeaf = await parseCertificate(leaf.der, { now: NOW });
    expect(parsedLeaf.isCA).toBe(false);
    expect(parsedLeaf.basicConstraints).toMatchObject({ present: true, ca: false, critical: true });

    const parsedIntermediate = await parseCertificate(intermediate.der, { now: NOW });
    expect(parsedIntermediate.isCA).toBe(true);
    expect(parsedIntermediate.basicConstraints.pathLength).toBe(0);
    expect(parsedIntermediate.isSelfSigned).toBe(false);

    const parsedRoot = await parseCertificate(root.der, { now: NOW });
    expect(parsedRoot.isCA).toBe(true);
    expect(parsedRoot.isSelfSigned).toBe(true);
  });

  it('detects a self-signed end-entity certificate', async () => {
    const { selfSignedLeaf } = await fixtures();
    const parsed = await parseCertificate(selfSignedLeaf.der, { now: NOW });

    expect(parsed.isSelfSigned).toBe(true);
    expect(parsed.isCA).toBe(false);
  });

  it('produces SHA-256 and SHA-1 fingerprints in colon-hex', async () => {
    const { leaf } = await fixtures();
    const parsed = await parseCertificate(leaf.der, { now: NOW });

    expect(parsed.fingerprints.sha256.split(':')).toHaveLength(32);
    expect(parsed.fingerprints.sha1.split(':')).toHaveLength(20);
    expect(parsed.id).toBe(parsed.fingerprints.sha256.replace(/:/g, ''));
  });

  it('lists extensions with name, OID and critical flag', async () => {
    const { leaf } = await fixtures();
    const parsed = await parseCertificate(leaf.der, { now: NOW });

    const names = parsed.extensions.map((extension) => extension.name);
    expect(names).toContain('Subject Alternative Name');
    expect(names).toContain('Basic Constraints');
    expect(names).toContain('Key Usage');
    expect(names).toContain('Extended Key Usage');
    expect(names).toContain('Subject Key Identifier');
    expect(names).toContain('Authority Key Identifier');

    const keyUsage = parsed.extensions.find((e) => e.oid === '2.5.29.15');
    expect(keyUsage?.critical).toBe(true);
    expect(keyUsage?.value).toBe('Digital Signature, Key Encipherment');

    const aki = parsed.extensions.find((e) => e.oid === '2.5.29.35');
    expect(aki?.value).toMatch(/^keyid: [0-9A-F]{2}(:[0-9A-F]{2}){19}$/);
  });

  it('links AKI to the issuer SKI', async () => {
    const { leaf, intermediate } = await fixtures();
    const parsedLeaf = await parseCertificate(leaf.der, { now: NOW });
    const parsedIntermediate = await parseCertificate(intermediate.der, { now: NOW });

    expect(parsedLeaf.authorityKeyIdentifier).toBe(
      parsedIntermediate.subjectKeyIdentifier,
    );
  });

  it('round-trips to PEM', async () => {
    const { leaf } = await fixtures();
    const parsed = await parseCertificate(leaf.der, { now: NOW });

    expect(parsed.pem.startsWith('-----BEGIN CERTIFICATE-----')).toBe(true);
    expect(parsed.pem.trimEnd().endsWith('-----END CERTIFICATE-----')).toBe(true);
    expect(parsed.pem).toBe(leaf.pem);
  });

  it('rejects data that is not a certificate', async () => {
    await expect(
      parseCertificate(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01])),
    ).rejects.toThrow(/not a valid X.509 certificate/);
  });
});

describe('buildValidity', () => {
  it('rounds remaining days away from zero on both sides', () => {
    const now = new Date('2026-08-12T12:00:00Z');
    const half = buildValidity(
      new Date('2026-01-01T00:00:00Z'),
      new Date('2026-08-13T00:00:00Z'),
      now,
    );
    expect(half.daysRemaining).toBe(1);

    const past = buildValidity(
      new Date('2025-01-01T00:00:00Z'),
      new Date('2026-08-12T00:00:00Z'),
      now,
    );
    expect(past.daysRemaining).toBe(-1);
    expect(past.status).toBe('expired');
  });
});
