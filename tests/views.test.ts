import { describe, expect, it } from 'vitest';

import { certificateAsn1Tree } from '../src/lib/certificate/asn1-tree';
import { opensslView } from '../src/lib/certificate/openssl-view';
import { parseCertificate } from '../src/lib/certificate/parse-certificate';
import { bytesToIpAddress, formatUtc, formatOpenSslDate } from '../src/lib/certificate/encoding';
import { NOW, fixtures } from './fixtures';

describe('certificateAsn1Tree', () => {
  it('labels the top-level X.509 structure', async () => {
    const { leaf } = await fixtures();
    const tree = certificateAsn1Tree(leaf.der)!;

    expect(tree.name).toBe('Certificate');
    expect(tree.type).toBe('SEQUENCE');
    expect(tree.children?.map((child) => child.name)).toEqual([
      'tbsCertificate',
      'signatureAlgorithm',
      'signatureValue',
    ]);
  });

  it('labels the tbsCertificate fields in order', async () => {
    const { leaf } = await fixtures();
    const tree = certificateAsn1Tree(leaf.der)!;
    const names = tree.children![0].children!.map((child) => child.name);

    expect(names.slice(0, 8)).toEqual([
      'version',
      'serialNumber',
      'signature',
      'issuer (RDNSequence)',
      'validity',
      'subject (RDNSequence)',
      'subjectPublicKeyInfo',
      'extensions',
    ]);
  });

  it('names extensions and decodes their payload', async () => {
    const { leaf } = await fixtures();
    const tree = certificateAsn1Tree(leaf.der)!;
    const extensions = tree
      .children![0].children!.find((child) => child.name === 'extensions')!
      .children![0].children!;

    expect(extensions.map((e) => e.name)).toContain(
      'Extension: Subject Alternative Name',
    );

    const san = extensions.find((e) => e.name.includes('Subject Alternative Name'))!;
    const extnValue = san.children!.find((child) => child.name === 'extnValue')!;
    expect(extnValue.children?.[0].name).toBe('SEQUENCE (decoded)');
  });

  it('records real offsets and lengths', async () => {
    const { leaf } = await fixtures();
    const tree = certificateAsn1Tree(leaf.der)!;

    expect(tree.offset).toBe(0);
    expect(tree.length).toBe(leaf.der.length);
    const tbs = tree.children![0];
    expect(tbs.offset).toBeGreaterThan(0);
    expect(tbs.offset + tbs.length).toBeLessThanOrEqual(leaf.der.length);
  });

  it('decodes a serial number and an OID correctly', async () => {
    const { leaf } = await fixtures();
    const tbs = certificateAsn1Tree(leaf.der)!.children![0];
    const serial = tbs.children!.find((child) => child.name === 'serialNumber')!;
    expect(serial.value).toBe('100');

    const signature = tbs.children!.find((child) => child.name === 'signature')!;
    expect(signature.children![0].name).toBe('algorithm (sha256WithRSAEncryption)');
    expect(signature.children![0].value).toBe('1.2.840.113549.1.1.11');

    const subject = tbs.children!.find((child) => child.name === 'subject (RDNSequence)')!;
    const firstAttribute = subject.children![0].children![0];
    expect(firstAttribute.children![0].name).toBe('type (Common Name)');
  });
});

describe('opensslView', () => {
  it('renders the familiar openssl x509 -text layout', async () => {
    const { leaf } = await fixtures();
    const parsed = await parseCertificate(leaf.der, { now: NOW });
    const text = opensslView(parsed);

    expect(text).toContain('Certificate:');
    expect(text).toContain('    Data:');
    expect(text).toContain('        Version: 3 (0x2)');
    expect(text).toContain('        Validity');
    expect(text).toContain('            Not Before: ');
    expect(text).toContain('            Not After : ');
    expect(text).toContain('        Subject Public Key Info:');
    expect(text).toContain('            Public Key Algorithm: rsaEncryption');
    expect(text).toContain('                Public-Key: (2048 bit)');
    expect(text).toContain('                Exponent: 65537 (0x10001)');
    expect(text).toContain('        X509v3 extensions:');
    expect(text).toContain('            X509v3 Subject Alternative Name:');
    expect(text).toContain('            X509v3 Key Usage: critical');
  });

  it('renders EC keys with the curve', async () => {
    const { eccLeaf } = await fixtures();
    const parsed = await parseCertificate(eccLeaf.der, { now: NOW });
    const text = opensslView(parsed);

    expect(text).toContain('Public Key Algorithm: id-ecPublicKey');
    expect(text).toContain('ASN1 OID: prime256v1 / secp256r1');
    expect(text).toContain('NIST CURVE: P-256');
  });
});

describe('encoding helpers', () => {
  it('renders IPv4 and IPv6 SAN octets', () => {
    expect(bytesToIpAddress(new Uint8Array([10, 20, 30, 40]))).toBe('10.20.30.40');
    expect(
      bytesToIpAddress(
        new Uint8Array([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
      ),
    ).toBe('2001:db8::1');
  });

  it('formats dates in UTC and in openssl style', () => {
    const date = new Date('2026-01-12T00:00:00Z');
    expect(formatUtc(date)).toBe('2026-01-12 00:00:00 UTC');
    expect(formatOpenSslDate(date)).toBe('Jan 12 00:00:00 2026 GMT');
  });
});
