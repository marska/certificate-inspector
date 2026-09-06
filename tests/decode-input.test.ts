import { describe, expect, it } from 'vitest';

import { decodeInput } from '../src/lib/certificate/decode-input';
import { detectFormat } from '../src/lib/certificate/detect-format';
import { bytesToBase64 } from '../src/lib/certificate/encoding';
import { bundle, fixtures } from './fixtures';

describe('decodeInput', () => {
  it('decodes a single PEM certificate', async () => {
    const { leaf } = await fixtures();
    const result = decodeInput(leaf.pem);

    expect(result.detectedFormat).toBe('pem');
    expect(result.blocks).toHaveLength(1);
    expect(result.blocks[0].der).toEqual(leaf.der);
    expect(result.issues).toEqual([]);
  });

  it('tolerates surrounding noise, CRLF and missing trailing newline', async () => {
    const { leaf } = await fixtures();
    const messy = `some log line\r\n${leaf.pem.replace(/\n/g, '\r\n')}\r\ntrailing text`;
    const result = decodeInput(messy);

    expect(result.blocks).toHaveLength(1);
    expect(result.blocks[0].der).toEqual(leaf.der);
  });

  it('decodes several PEM certificates from one bundle', async () => {
    const { leaf, intermediate, root } = await fixtures();
    const result = decodeInput(bundle(leaf, intermediate, root));

    expect(result.blocks).toHaveLength(3);
    expect(result.blocks.map((block) => block.der)).toEqual([
      leaf.der,
      intermediate.der,
      root.der,
    ]);
  });

  it('decodes raw base64 DER without PEM armour', async () => {
    const { leaf } = await fixtures();
    const result = decodeInput(bytesToBase64(leaf.der));

    expect(result.detectedFormat).toBe('base64-der');
    expect(result.blocks[0].der).toEqual(leaf.der);
  });

  it('decodes base64 that wraps a whole PEM file (double encoding)', async () => {
    const { leaf } = await fixtures();
    const encoded = Buffer.from(leaf.pem, 'utf8').toString('base64');
    const result = decodeInput(encoded);

    expect(result.detectedFormat).toBe('base64-pem');
    expect(result.blocks).toHaveLength(1);
    expect(result.blocks[0].der).toEqual(leaf.der);
  });

  it('decodes base64 wrapping a multi-certificate PEM bundle', async () => {
    const { leaf, intermediate } = await fixtures();
    const encoded = Buffer.from(bundle(leaf, intermediate), 'utf8').toString('base64');
    const result = decodeInput(encoded);

    expect(result.blocks).toHaveLength(2);
  });

  it('decodes binary DER from a file upload', async () => {
    const { leaf } = await fixtures();
    const result = decodeInput(leaf.der);

    expect(result.detectedFormat).toBe('der');
    expect(result.blocks[0].der).toEqual(leaf.der);
  });

  it('splits concatenated DER certificates', async () => {
    const { leaf, intermediate } = await fixtures();
    const joined = new Uint8Array(leaf.der.length + intermediate.der.length);
    joined.set(leaf.der);
    joined.set(intermediate.der, leaf.der.length);

    const result = decodeInput(joined);
    expect(result.blocks).toHaveLength(2);
  });

  it('decodes hex input', async () => {
    const { leaf } = await fixtures();
    const hex = Buffer.from(leaf.der).toString('hex');
    const result = decodeInput(hex);

    expect(result.detectedFormat).toBe('hex');
    expect(result.blocks[0].der).toEqual(leaf.der);
  });

  it('reports a missing END line instead of a generic failure', async () => {
    const { leaf } = await fixtures();
    const broken = leaf.pem.replace('-----END CERTIFICATE-----', '');
    const result = decodeInput(broken);

    expect(result.blocks).toHaveLength(0);
    expect(result.issues[0]).toMatchObject({
      code: 'PEM_MISSING_END',
      severity: 'error',
    });
    expect(result.issues[0].message).toContain('END CERTIFICATE');
  });

  it('reports a missing BEGIN line', async () => {
    const { leaf } = await fixtures();
    const broken = leaf.pem.replace('-----BEGIN CERTIFICATE-----', '');
    const result = decodeInput(broken);

    expect(result.issues.some((issue) => issue.code === 'PEM_MISSING_BEGIN')).toBe(true);
  });

  it('reports invalid base64 characters', () => {
    const result = decodeInput('MIIEFTCCAv2gAwIBAgIU!!!not-base64$$$MIIEFTCCAv2gAwIBAgIU');

    expect(result.issues[0]).toMatchObject({ code: 'INVALID_BASE64', severity: 'error' });
    expect(result.issues[0].detail).toContain('"!"');
  });

  it('reports truncated base64', async () => {
    const { leaf } = await fixtures();
    const encoded = bytesToBase64(leaf.der);
    const result = decodeInput(encoded.slice(0, Math.floor(encoded.length / 2)));

    const codes = result.issues.map((issue) => issue.code);
    expect(codes).toContain('TRUNCATED_DER');
    expect(result.blocks).toHaveLength(0);
  });

  it('reports incomplete base64 whose length is not a multiple of four', async () => {
    const { leaf } = await fixtures();
    const encoded = bytesToBase64(leaf.der).replace(/=+$/, '');
    const result = decodeInput(`${encoded.slice(0, encoded.length - 3)}A`);

    expect(result.issues.some((issue) => issue.code === 'INCOMPLETE_BASE64')).toBe(true);
  });

  it('detects a pasted private key and never treats it as a certificate', () => {
    const input = [
      '-----BEGIN PRIVATE KEY-----',
      'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj',
      '-----END PRIVATE KEY-----',
    ].join('\n');
    const result = decodeInput(input);

    expect(result.containsPrivateKey).toBe(true);
    expect(result.blocks).toHaveLength(0);
    expect(result.issues.some((issue) => issue.code === 'PRIVATE_KEY_DETECTED')).toBe(true);
  });

  it('detects an RSA private key header too', () => {
    const result = decodeInput(
      '-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQ==\n-----END RSA PRIVATE KEY-----',
    );
    expect(result.containsPrivateKey).toBe(true);
  });

  it('still shows the certificate when a key and a certificate are pasted together', async () => {
    const { leaf } = await fixtures();
    const input = `-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----\n\n${leaf.pem}`;
    const result = decodeInput(input);

    expect(result.containsPrivateKey).toBe(true);
    expect(result.blocks).toHaveLength(1);
  });

  it('recognises a CSR and says so', () => {
    const result = decodeInput(
      '-----BEGIN CERTIFICATE REQUEST-----\nMIICijCCAXICAQAwRTEL\n-----END CERTIFICATE REQUEST-----',
    );
    expect(result.issues.some((issue) => issue.code === 'CSR_DETECTED')).toBe(true);
  });

  it('reports empty input as empty, not as an error', () => {
    const result = decodeInput('   \n  ');
    expect(result.detectedFormat).toBe('empty');
    expect(result.issues).toEqual([]);
    expect(result.blocks).toEqual([]);
  });

  it('reports plain prose as "no certificate found"', () => {
    const result = decodeInput('please decode my certificate, thanks');
    expect(result.issues[0].code).toBe('NO_CERTIFICATE_FOUND');
  });

  it('reports a non-certificate DER structure', () => {
    // SEQUENCE { INTEGER 1 } — valid DER, not a certificate.
    const result = decodeInput(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]));
    expect(result.issues[0].code).toBe('NOT_DER');
  });
});

describe('detectFormat', () => {
  it('classifies each input shape', async () => {
    const { leaf } = await fixtures();

    expect(detectFormat('')).toBe('empty');
    expect(detectFormat(leaf.pem)).toBe('pem');
    expect(detectFormat(leaf.der)).toBe('der');
    expect(detectFormat(bytesToBase64(leaf.der))).toBe('base64-der');
    expect(detectFormat(Buffer.from(leaf.der).toString('hex'))).toBe('hex');
    expect(detectFormat('-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----')).toBe(
      'private-key',
    );
    expect(detectFormat('hello world')).toBe('unknown');
  });
});
